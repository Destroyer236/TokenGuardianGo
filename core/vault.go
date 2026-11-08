// vault.go 实现 Authenticator 的加密保险库。
//
// 相比 Python 版（AES-256-CBC + 固定盐 PBKDF2）的存储设计，本实现升级为：
//   - AES-256-GCM（认证加密：篡改或密码错误都会校验失败）
//   - Argon2id 密钥派生（每库独立随机盐，64MB 内存参数，抗 GPU 爆破）
//   - 临时文件 + rename 的原子写入
//
// 文件布局：magic(5) + version(1) + salt(16) + nonce(12) + GCM 密文(JSON 明细)。
// 保险库自身的盐在创建/打开时生成并随 Vault 记忆，后续每次保存复用同一盐；
// 导出文件使用独立密码与独立随机盐。
package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	vaultMagic   = "TGVLT" // 固定文件头（历史遗留：TokenGuardian Vault），不可更改，否则旧保险库无法识别
	vaultVersion = byte(1)
	saltSize     = 16
	nonceSize    = 12
	keySize      = 32
	headerSize   = len(vaultMagic) + 1 + saltSize + nonceSize
)

// Argon2id KDF 参数（可按需调整；64MiB 在桌面端解锁约需数百毫秒）。
var (
	Argon2Memory  uint32 = 64 * 1024 // KiB
	Argon2Time    uint32 = 3
	Argon2Threads uint8  = 1
)

// 业务错误（文案与前端 UI 对齐）。
var (
	ErrWrongPassword = errors.New("密码错误")
	ErrVaultExists   = errors.New("保险库已存在")
	ErrVaultLocked   = errors.New("保险库未解锁")
	ErrNameExists    = errors.New("密钥名称已存在")
	ErrNotFound      = errors.New("密钥不存在")
	ErrBadAlgo       = errors.New("算法模式必须是 TOTP 或 HOTP")
)

// Algo 常量。
const (
	AlgoTOTP = "TOTP"
	AlgoHOTP = "HOTP"
)

// Entry 是保险库中的一条 2FA 密钥。
type Entry struct {
	Name      string    `json:"name"`
	Secret    string    `json:"secret"` // Base32
	Algo      string    `json:"algo"`   // TOTP | HOTP
	Counter   uint64    `json:"counter"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type vaultPayload struct {
	Entries []Entry `json:"entries"`
	// Deleted 是已删除密钥的墓碑（名称+删除时刻），用于多端同步时传播删除操作。
	// 旧版本保险库文件无此字段，JSON 解析时自然为零值，保持向后兼容。
	Deleted []Entry `json:"deleted,omitempty"`
}

// Vault 是已解锁的保险库。派生密钥只保存在内存中。
// 所有方法并发安全（内部互斥锁），后台同步与 UI 操作可同时进行。
type Vault struct {
	mu      sync.Mutex
	path    string
	salt    []byte // 保险库自身盐（创建/打开时确定，保存时复用）
	key     []byte // 由主密码+盐派生
	entries []Entry
	deleted []Entry // 墓碑：已删除密钥的名称与删除时间
}

// DefaultVaultPath 返回默认保险库路径：程序所在目录下的 vault.enc（Windows 隐藏属性）。
// 便携式设计：删除该文件即可重置主密码、重新开始。
func DefaultVaultPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		// 取不到可执行文件路径时退回工作目录
		return "vault.enc", nil
	}
	return filepath.Join(filepath.Dir(exe), "vault.enc"), nil
}

// VaultFileExists 判断指定路径是否已存在保险库文件。
func VaultFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, keySize)
}

// encryptBlob 用给定密钥加密明文，返回 magic+version+salt+nonce+密文 的完整文件镜像。
func encryptBlob(plaintext, key, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerSize+len(plaintext)+gcm.Overhead())
	out = append(out, vaultMagic...)
	out = append(out, vaultVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// parseVaultHeader 校验保险库文件头，返回盐与 nonce。
func parseVaultHeader(blob []byte) (salt, nonce []byte, err error) {
	if len(blob) < headerSize || string(blob[:len(vaultMagic)]) != vaultMagic {
		return nil, nil, errors.New("不是有效的 Authenticator 保险库文件")
	}
	if blob[len(vaultMagic)] != vaultVersion {
		return nil, nil, fmt.Errorf("保险库版本不受支持: %d", blob[len(vaultMagic)])
	}
	salt = blob[len(vaultMagic)+1 : len(vaultMagic)+1+saltSize]
	nonce = blob[len(vaultMagic)+1+saltSize : headerSize]
	return salt, nonce, nil
}

// gcmOpen 认证解密；密钥错误或密文被篡改时失败。
func gcmOpen(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// decryptWithPassword 解密文件镜像；密码错误或数据被篡改时返回 ErrWrongPassword。
func decryptWithPassword(blob, password []byte) ([]byte, []byte, error) {
	salt, nonce, err := parseVaultHeader(blob)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := gcmOpen(blob[headerSize:], deriveKey(string(password), salt), nonce)
	if err != nil {
		return nil, nil, ErrWrongPassword
	}
	return plaintext, salt, nil
}

// decryptWithKey 用已派生的密钥解密文件镜像（快速解锁路径，跳过 Argon2 派生）。
func decryptWithKey(blob, key []byte) ([]byte, []byte, error) {
	salt, nonce, err := parseVaultHeader(blob)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := gcmOpen(blob[headerSize:], key, nonce)
	if err != nil {
		return nil, nil, ErrWrongPassword
	}
	return plaintext, salt, nil
}

// writeVaultFile 原子写入：先写临时文件再 rename 覆盖。
func writeVaultFile(path string, blob []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Create 创建全新保险库并解锁；文件已存在时返回 ErrVaultExists。
func Create(path, password string) (*Vault, error) {
	if VaultFileExists(path) {
		return nil, ErrVaultExists
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	v := &Vault{
		path:    path,
		salt:    salt,
		key:     deriveKey(password, salt),
		entries: []Entry{},
	}
	if err := v.save(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open 读取并解密保险库；密码错误返回 ErrWrongPassword。
func Open(path, password string) (*Vault, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plaintext, salt, err := decryptWithPassword(blob, []byte(password))
	if err != nil {
		return nil, err
	}
	var payload vaultPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("保险库数据损坏: %w", err)
	}
	if payload.Entries == nil {
		payload.Entries = []Entry{}
	}
	return &Vault{
		path:    path,
		salt:    append([]byte(nil), salt...),
		key:     deriveKey(password, salt),
		entries: payload.Entries,
		deleted: payload.Deleted,
	}, nil
}

// OpenWithKey 用已派生的密钥直接打开保险库（指纹快速解锁路径，跳过 Argon2 派生）。
// 密钥与文件不匹配时返回 ErrWrongPassword。
func OpenWithKey(path string, key []byte) (*Vault, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plaintext, salt, err := decryptWithKey(blob, key)
	if err != nil {
		return nil, err
	}
	var payload vaultPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("保险库数据损坏: %w", err)
	}
	if payload.Entries == nil {
		payload.Entries = []Entry{}
	}
	return &Vault{
		path:    path,
		salt:    append([]byte(nil), salt...),
		key:     append([]byte(nil), key...),
		entries: payload.Entries,
		deleted: payload.Deleted,
	}, nil
}

// KeyCopy 返回派生密钥的副本（调用方用后应清零）；保险库未解锁时返回 ErrVaultLocked。
func (v *Vault) KeyCopy() ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return nil, ErrVaultLocked
	}
	out := make([]byte, len(v.key))
	copy(out, v.key)
	return out, nil
}

// save 用已缓存的密钥重新加密并原子写盘（nonce 每次随机，盐固定复用）。
// 调用方必须已持有 v.mu。
func (v *Vault) save() error {
	data, err := json.Marshal(vaultPayload{Entries: v.entries, Deleted: v.deleted})
	if err != nil {
		return err
	}
	blob, err := encryptBlob(data, v.key, v.salt)
	if err != nil {
		return err
	}
	if err := writeVaultFile(v.path, blob); err != nil {
		return err
	}
	// 原子替换产生的新文件会丢失隐藏属性，每次保存后重新标记
	_ = markHidden(v.path)
	return nil
}

// Close 锁定保险库：清零并释放内存中的密钥与明细。
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.key {
		v.key[i] = 0
	}
	for i := range v.salt {
		v.salt[i] = 0
	}
	v.key = nil
	v.salt = nil
	v.entries = nil
	v.deleted = nil
}

// Entries 返回明细副本。
func (v *Vault) Entries() []Entry {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Entry, len(v.entries))
	copy(out, v.entries)
	return out
}

// Deleted 返回墓碑副本。
func (v *Vault) Deleted() []Entry {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Entry, len(v.deleted))
	copy(out, v.deleted)
	return out
}

// Persist 将当前内存状态原子落盘（供合并后调用；普通增删改已自动保存）。
func (v *Vault) Persist() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrVaultLocked
	}
	return v.save()
}

// Get 按名称查找密钥。
func (v *Vault) Get(name string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, e := range v.entries {
		if e.Name == name {
			return e, nil
		}
	}
	return Entry{}, ErrNotFound
}

func validateEntry(name, secret, algo string) error {
	if name == "" {
		return errors.New("密钥名称不能为空")
	}
	if algo != AlgoTOTP && algo != AlgoHOTP {
		return ErrBadAlgo
	}
	return ValidateSecret(secret)
}

// Add 新增密钥；名称重复或密钥非法时返回错误。
func (v *Vault) Add(name, secret, algo string, counter uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrVaultLocked
	}
	if err := validateEntry(name, secret, algo); err != nil {
		return err
	}
	if v.getLocked(name) {
		return ErrNameExists
	}
	if algo != AlgoHOTP {
		counter = 0
	}
	v.entries = append(v.entries, Entry{Name: name, Secret: secret, Algo: algo, Counter: counter, UpdatedAt: time.Now()})
	return v.save()
}

// Remove 删除指定名称的密钥，并记录墓碑（同步时向其他设备传播删除）。
func (v *Vault) Remove(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrVaultLocked
	}
	for i, e := range v.entries {
		if e.Name == name {
			v.entries = append(v.entries[:i], v.entries[i+1:]...)
			v.recordTombstone(name)
			return v.save()
		}
	}
	return ErrNotFound
}

// recordTombstone 记录删除墓碑；同名墓碑已存在时更新为最新时间（调用方必须已持有 v.mu）。
func (v *Vault) recordTombstone(name string) {
	now := time.Now()
	for i := range v.deleted {
		if v.deleted[i].Name == name {
			v.deleted[i] = Entry{Name: name, UpdatedAt: now}
			return
		}
	}
	v.deleted = append(v.deleted, Entry{Name: name, UpdatedAt: now})
}

// Update 修改密钥（重命名、换密钥、换算法、改计数器）。
func (v *Vault) Update(oldName, newName, secret, algo string, counter uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrVaultLocked
	}
	if err := validateEntry(newName, secret, algo); err != nil {
		return err
	}
	if newName != oldName && v.getLocked(newName) {
		return ErrNameExists
	}
	for i := range v.entries {
		if v.entries[i].Name == oldName {
			if algo != AlgoHOTP {
				counter = 0
			}
			v.entries[i] = Entry{Name: newName, Secret: secret, Algo: algo, Counter: counter, UpdatedAt: time.Now()}
			return v.save()
		}
	}
	return ErrNotFound
}

// getLocked 按名称判断密钥是否存在（调用方必须已持有 v.mu）。
func (v *Vault) getLocked(name string) bool {
	for _, e := range v.entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

// IncrementCounter 将 HOTP 计数器 +1 并返回新计数器值。
func (v *Vault) IncrementCounter(name string) (uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return 0, ErrVaultLocked
	}
	for i := range v.entries {
		if v.entries[i].Name == name {
			if v.entries[i].Algo != AlgoHOTP {
				return 0, errors.New("仅 HOTP 密钥可以递增计数器")
			}
			v.entries[i].Counter++
			v.entries[i].UpdatedAt = time.Now()
			if err := v.save(); err != nil {
				return 0, err
			}
			return v.entries[i].Counter, nil
		}
	}
	return 0, ErrNotFound
}

// ExportEntries 将指定密钥（entries 传 nil 时导出全部）加密导出到文件，使用独立密码与独立随机盐。
func (v *Vault) ExportEntries(entries []Entry, path, password string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrVaultLocked
	}
	if entries == nil {
		entries = v.entries
	}
	data, err := json.Marshal(vaultPayload{Entries: entries})
	if err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	exportKey := deriveKey(password, salt)
	blob, err := encryptBlob(data, exportKey, salt)
	if err != nil {
		return err
	}
	return writeVaultFile(path, blob)
}

// Import 从加密文件（与导出格式一致，独立密码）导入密钥；重名或非法条目跳过。
// 返回成功导入的条数。
func (v *Vault) Import(path, password string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return 0, ErrVaultLocked
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	plaintext, _, err := decryptWithPassword(blob, []byte(password))
	if err != nil {
		return 0, err
	}
	var payload vaultPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return 0, fmt.Errorf("导入文件数据损坏: %w", err)
	}
	imported := 0
	for _, e := range payload.Entries {
		if v.getLocked(e.Name) {
			continue // 已存在则跳过
		}
		if err := validateEntry(e.Name, e.Secret, e.Algo); err != nil {
			continue // 非法条目跳过
		}
		if e.Algo != AlgoHOTP {
			e.Counter = 0
		}
		e.UpdatedAt = time.Now()
		v.entries = append(v.entries, e)
		imported++
	}
	if imported > 0 {
		if err := v.save(); err != nil {
			return 0, err
		}
	}
	return imported, nil
}

// MergeResult 描述一次合并对本地保险库产生的变更数量。
type MergeResult struct {
	Added   int
	Updated int
	Deleted int
}

// Changed 是否有本地变更需要落盘。
func (r MergeResult) Changed() bool {
	return r.Added != 0 || r.Updated != 0 || r.Deleted != 0
}

// MergeFrom 将远端条目与墓碑按名称做双向合并（last-write-wins）：
//   - 双方同名的条目：UpdatedAt 更新者胜，相同则保留本地；
//   - 远端墓碑比本地条目新：本地删除该条目（删除传播）；
//   - 本地条目比远端墓碑新（删除后又被修改）：条目复活，过期墓碑清除；
//   - 本地不存在且被更新墓碑遮蔽的远端条目：保持删除状态；
//   - 墓碑列表本身也双向合并（各保留每个名称最新的墓碑）。
//
// 非法条目（空名称 / 未知算法 / 无效 Base32）跳过。合并结果只改内存，
// 由调用方决定是否调用 Persist 落盘。
func (v *Vault) MergeFrom(remoteEntries, remoteDeleted []Entry) (MergeResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return MergeResult{}, ErrVaultLocked
	}
	var res MergeResult

	entries := make(map[string]Entry, len(v.entries))
	for _, e := range v.entries {
		entries[e.Name] = e
	}
	tombs := make(map[string]time.Time, len(v.deleted))
	for _, d := range v.deleted {
		tombs[d.Name] = d.UpdatedAt
	}

	// 1. 远端条目并入本地
	for _, re := range remoteEntries {
		if validateEntry(re.Name, re.Secret, re.Algo) != nil {
			continue
		}
		le, exists := entries[re.Name]
		switch {
		case !exists:
			if t, wasDeleted := tombs[re.Name]; wasDeleted {
				if !re.UpdatedAt.After(t) {
					continue // 墓碑不旧于条目：保持删除
				}
				delete(tombs, re.Name) // 条目比墓碑新：复活并清除过期墓碑
			}
			entries[re.Name] = re
			res.Added++
		case re.UpdatedAt.After(le.UpdatedAt):
			entries[re.Name] = re
			res.Updated++
		}
	}

	// 2. 远端墓碑并入本地（旧于现存条目的墓碑已被条目本身否定，不记录，
	//    避免墓碑集合随时间无限膨胀）
	for _, rd := range remoteDeleted {
		if rd.Name == "" {
			continue
		}
		lt, hasTomb := tombs[rd.Name]
		le, exists := entries[rd.Name]
		if (!hasTomb || rd.UpdatedAt.After(lt)) && (!exists || rd.UpdatedAt.After(le.UpdatedAt)) {
			tombs[rd.Name] = rd.UpdatedAt
		}
		if exists && rd.UpdatedAt.After(le.UpdatedAt) {
			delete(entries, rd.Name)
			res.Deleted++
		}
	}

	// 3. 按原有顺序重建条目切片（更新沿用原位置，新增追加在尾部并按名称排序）
	out := make([]Entry, 0, len(entries))
	for _, e := range v.entries {
		if ne, ok := entries[e.Name]; ok {
			out = append(out, ne)
			delete(entries, e.Name)
		}
	}
	added := make([]string, 0, len(entries))
	for name := range entries {
		added = append(added, name)
	}
	sort.Strings(added)
	for _, name := range added {
		out = append(out, entries[name])
	}

	// 4. 重建墓碑切片（按名称排序保证确定性）
	outD := make([]Entry, 0, len(tombs))
	for name, t := range tombs {
		outD = append(outD, Entry{Name: name, UpdatedAt: t})
	}
	sort.Slice(outD, func(i, j int) bool { return outD[i].Name < outD[j].Name })

	v.entries = out
	v.deleted = outD
	return res, nil
}
