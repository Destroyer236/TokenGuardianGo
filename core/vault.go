// vault.go 实现 TokenGuardian Go 的加密保险库。
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
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	vaultMagic   = "TGVLT" // TokenGuardian Vault
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
}

// Vault 是已解锁的保险库。派生密钥只保存在内存中。
type Vault struct {
	path    string
	salt    []byte // 保险库自身盐（创建/打开时确定，保存时复用）
	key     []byte // 由主密码+盐派生
	entries []Entry
}

// DefaultVaultPath 返回默认保险库路径：%AppData%/TokenGuardian/vault.enc
func DefaultVaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "TokenGuardian", "vault.enc"), nil
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

// decryptWithPassword 解密文件镜像；密码错误或数据被篡改时返回 ErrWrongPassword。
func decryptWithPassword(blob, password []byte) ([]byte, []byte, error) {
	if len(blob) < headerSize || string(blob[:len(vaultMagic)]) != vaultMagic {
		return nil, nil, errors.New("不是有效的 TokenGuardian 保险库文件")
	}
	if blob[len(vaultMagic)] != vaultVersion {
		return nil, nil, fmt.Errorf("保险库版本不受支持: %d", blob[len(vaultMagic)])
	}
	salt := blob[len(vaultMagic)+1 : len(vaultMagic)+1+saltSize]
	nonce := blob[len(vaultMagic)+1+saltSize : headerSize]
	key := deriveKey(string(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, blob[headerSize:], nil)
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
	}, nil
}

// save 用已缓存的密钥重新加密并原子写盘（nonce 每次随机，盐固定复用）。
func (v *Vault) save() error {
	data, err := json.Marshal(vaultPayload{Entries: v.entries})
	if err != nil {
		return err
	}
	blob, err := encryptBlob(data, v.key, v.salt)
	if err != nil {
		return err
	}
	return writeVaultFile(v.path, blob)
}

// Close 锁定保险库：清零并释放内存中的密钥与明细。
func (v *Vault) Close() {
	for i := range v.key {
		v.key[i] = 0
	}
	for i := range v.salt {
		v.salt[i] = 0
	}
	v.key = nil
	v.salt = nil
	v.entries = nil
}

// Entries 返回明细副本。
func (v *Vault) Entries() []Entry {
	out := make([]Entry, len(v.entries))
	copy(out, v.entries)
	return out
}

// Get 按名称查找密钥。
func (v *Vault) Get(name string) (Entry, error) {
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
	if v.key == nil {
		return ErrVaultLocked
	}
	if err := validateEntry(name, secret, algo); err != nil {
		return err
	}
	if _, err := v.Get(name); err == nil {
		return ErrNameExists
	}
	if algo != AlgoHOTP {
		counter = 0
	}
	v.entries = append(v.entries, Entry{Name: name, Secret: secret, Algo: algo, Counter: counter, UpdatedAt: time.Now()})
	return v.save()
}

// Remove 删除指定名称的密钥。
func (v *Vault) Remove(name string) error {
	if v.key == nil {
		return ErrVaultLocked
	}
	for i, e := range v.entries {
		if e.Name == name {
			v.entries = append(v.entries[:i], v.entries[i+1:]...)
			return v.save()
		}
	}
	return ErrNotFound
}

// Update 修改密钥（重命名、换密钥、换算法、改计数器）。
func (v *Vault) Update(oldName, newName, secret, algo string, counter uint64) error {
	if v.key == nil {
		return ErrVaultLocked
	}
	if err := validateEntry(newName, secret, algo); err != nil {
		return err
	}
	if newName != oldName {
		if _, err := v.Get(newName); err == nil {
			return ErrNameExists
		}
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

// IncrementCounter 将 HOTP 计数器 +1 并返回新计数器值。
func (v *Vault) IncrementCounter(name string) (uint64, error) {
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
		if _, err := v.Get(e.Name); err == nil {
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
