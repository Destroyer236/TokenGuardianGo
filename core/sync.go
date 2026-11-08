// sync.go 实现 TokenGuardian Go 的 WebDAV 多端同步。
//
// 设计要点：
//   - 云端只存密文：同步文件复用保险库 .enc 格式（TGVLT 头 + Argon2id 派生 +
//     AES-256-GCM），使用与主密码无关的独立同步密码加密；
//   - 合并优先于覆盖（KeePass 式）：拉取远端 → 条目级 last-write-wins 合并 →
//     本地落盘 → 推送合并结果，删除操作经墓碑记录传播；
//   - 同步配置保存在程序同目录的 webdav.enc，直接用保险库解锁后的内存派生密钥
//     加密（无需 Argon2 二次派生）：锁定即不可读，随 vault.enc 拷贝即可在
//     新设备恢复全部配置。
//
// 配置文件布局：magic(5) + version(1) + nonce(12) + GCM 密文(JSON 配置)。
package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/studio-b12/gowebdav"
)

const (
	syncCfgMagic     = "TGWCF" // TokenGuardian WebDAV ConFig
	syncCfgVersion   = byte(1)
	syncCfgNonceSize = 12
	// DefaultRemotePath 是远端同步文件的默认路径（相对 WebDAV 根目录）。
	DefaultRemotePath = "TokenGuardianGo/sync.enc"
	// webdavTimeout 是单次 WebDAV 请求的超时。
	webdavTimeout = 15 * time.Second
)

// SyncConfig 描述一个 WebDAV 同步配置。
type SyncConfig struct {
	ServerURL      string `json:"serverUrl"`      // WebDAV 根地址，如 https://dav.jianguoyun.com/dav/
	Username       string `json:"username"`       // 账号（匿名服务器可为空）
	WebDAVPassword string `json:"webdavPassword"` // 账号密码 / 应用密码
	SyncPassword   string `json:"syncPassword"`   // 同步文件加密密码（独立于主密码）
	RemotePath     string `json:"remotePath"`     // 远端文件路径，如 TokenGuardianGo/sync.enc
}

// Validate 校验配置合法性。
func (c *SyncConfig) Validate() error {
	u, err := url.Parse(strings.TrimSpace(c.ServerURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("服务器地址无效，需以 http:// 或 https:// 开头")
	}
	if c.SyncPassword == "" {
		return errors.New("同步密码不能为空")
	}
	for _, seg := range strings.Split(filepath.ToSlash(c.RemotePath), "/") {
		if seg == ".." {
			return errors.New("远端路径不能包含 ..")
		}
	}
	return nil
}

// Normalize 归一化：远端路径去掉首尾空白与开头的 /，空路径用默认值。
func (c *SyncConfig) Normalize() {
	c.ServerURL = strings.TrimRight(strings.TrimSpace(c.ServerURL), "/")
	c.RemotePath = strings.Trim(strings.TrimSpace(filepath.ToSlash(c.RemotePath)), "/")
	if c.RemotePath == "" {
		c.RemotePath = DefaultRemotePath
	}
}

// SyncConfigPath 返回与保险库同目录的同步配置文件路径（webdav.enc）。
func SyncConfigPath(vaultPath string) string {
	return filepath.Join(filepath.Dir(vaultPath), "webdav.enc")
}

// LoadSyncConfig 读取用 v 的派生密钥加密的同步配置；文件不存在时返回 (nil, nil)。
func LoadSyncConfig(path string, v *Vault) (*SyncConfig, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return nil, ErrVaultLocked
	}
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := decryptConfigBlob(blob, v.key)
	if err != nil {
		return nil, err
	}
	var cfg SyncConfig
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, fmt.Errorf("同步配置损坏: %w", err)
	}
	cfg.Normalize()
	return &cfg, nil
}

// SaveSyncConfig 用 v 的派生密钥加密并原子写入同步配置。
func SaveSyncConfig(path string, v *Vault, cfg *SyncConfig) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrVaultLocked
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	nonce := make([]byte, syncCfgNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(syncCfgMagic)+1+syncCfgNonceSize+len(data)+gcm.Overhead())
	out = append(out, syncCfgMagic...)
	out = append(out, syncCfgVersion)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, data, nil)
	if err := writeVaultFile(path, out); err != nil {
		return err
	}
	_ = markHidden(path)
	return nil
}

// decryptConfigBlob 解密配置文件镜像；密钥不匹配（换了保险库）时返回明确错误。
func decryptConfigBlob(blob, key []byte) ([]byte, error) {
	if len(blob) < len(syncCfgMagic)+1+syncCfgNonceSize || string(blob[:len(syncCfgMagic)]) != syncCfgMagic {
		return nil, errors.New("不是有效的 TokenGuardian 同步配置文件")
	}
	if blob[len(syncCfgMagic)] != syncCfgVersion {
		return nil, fmt.Errorf("同步配置版本不受支持: %d", blob[len(syncCfgMagic)])
	}
	nonce := blob[len(syncCfgMagic)+1 : len(syncCfgMagic)+1+syncCfgNonceSize]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, blob[len(syncCfgMagic)+1+syncCfgNonceSize:], nil)
	if err != nil {
		// 常量时间比较失败原因不可区分，这里统一按密钥不匹配提示
		return nil, errors.New("同步配置无法解密（保险库主密码已更换？删除 webdav.enc 可重新配置）")
	}
	return plain, nil
}

// TestSyncConnection 验证 WebDAV 服务器连通性与认证是否可用。
func TestSyncConnection(serverURL, username, password string) error {
	c, err := newWebDAVClient(serverURL, username, password)
	if err != nil {
		return err
	}
	if err := c.Connect(); err != nil {
		return wrapWebDAVErr("连接服务器", err)
	}
	return nil
}

// newWebDAVClient 构造带超时的 gowebdav 客户端。
func newWebDAVClient(serverURL, username, password string) (*gowebdav.Client, error) {
	if strings.TrimSpace(serverURL) == "" {
		return nil, errors.New("服务器地址不能为空")
	}
	c := gowebdav.NewClient(strings.TrimRight(strings.TrimSpace(serverURL), "/"), username, password)
	c.SetTimeout(webdavTimeout)
	return c, nil
}

// RemoteFileInfo 描述远端同步文件的元信息。
type RemoteFileInfo struct {
	Exists  bool      `json:"exists"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"` // 服务器端最后修改时间
}

// StatRemote 查询远端同步文件元信息；文件不存在时 Exists=false 而非报错。
func StatRemote(v *Vault, cfg *SyncConfig) (RemoteFileInfo, error) {
	var info RemoteFileInfo
	if v == nil || cfg == nil {
		return info, errors.New("保险库未解锁或同步配置为空")
	}
	norm := *cfg
	norm.Normalize()
	if err := norm.Validate(); err != nil {
		return info, err
	}
	client, err := newWebDAVClient(norm.ServerURL, norm.Username, norm.WebDAVPassword)
	if err != nil {
		return info, err
	}
	fi, err := client.Stat(norm.RemotePath)
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			return info, nil // 尚未上传过
		}
		return info, wrapWebDAVErr("查询远端文件", err)
	}
	return RemoteFileInfo{Exists: true, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

// SyncResult 描述一次同步的结果（字段名与前端对齐）。
type SyncResult struct {
	Added         int  `json:"added"`         // 从远端并入的新增条数
	Updated       int  `json:"updated"`       // 被远端更新覆盖的条数
	Deleted       int  `json:"deleted"`       // 因远端墓碑而删除的条数
	RemoteExisted bool `json:"remoteExisted"` // 远端此前是否已有同步文件
	Pushed        bool `json:"pushed"`        // 是否推送了合并结果
}

// DoSync 执行一次完整同步：拉取远端 → 条目级合并 → 本地落盘 → 推送合并结果。
// 云端文件全程只以密文形式存在。
func DoSync(v *Vault, cfg *SyncConfig) (SyncResult, error) {
	res := SyncResult{}
	if v == nil || cfg == nil {
		return res, errors.New("保险库未解锁或同步配置为空")
	}
	norm := *cfg
	norm.Normalize()
	if err := norm.Validate(); err != nil {
		return res, err
	}
	client, err := newWebDAVClient(norm.ServerURL, norm.Username, norm.WebDAVPassword)
	if err != nil {
		return res, err
	}

	// 确保远端目录存在（每级 MKCOL，已存在时静默跳过）
	if dir := path.Dir(norm.RemotePath); dir != "." && dir != "/" {
		if err := client.MkdirAll(dir, 0o755); err != nil {
			return res, wrapWebDAVErr("创建远端目录", err)
		}
	}

	// 拉取远端（不存在视为空远端，首次同步）
	blob, err := client.Read(norm.RemotePath)
	if err != nil {
		if !gowebdav.IsErrNotFound(err) {
			return res, wrapWebDAVErr("读取远端同步文件", err)
		}
	} else {
		res.RemoteExisted = true
		plain, _, err := decryptWithPassword(blob, []byte(norm.SyncPassword))
		if err != nil {
			if errors.Is(err, ErrWrongPassword) {
				return res, errors.New("远端文件解密失败：同步密码错误，或该路径不是 TokenGuardian 同步文件")
			}
			return res, err
		}
		var payload vaultPayload
		if err := json.Unmarshal(plain, &payload); err != nil {
			return res, fmt.Errorf("远端同步文件数据损坏: %w", err)
		}
		mr, err := v.MergeFrom(payload.Entries, payload.Deleted)
		if err != nil {
			return res, err
		}
		res.Added, res.Updated, res.Deleted = mr.Added, mr.Updated, mr.Deleted
		if mr.Changed() {
			if err := v.Persist(); err != nil {
				return res, err
			}
		}
	}

	// 推送合并后的最新状态（独立随机盐 + 同步密码派生密钥）
	plain, err := v.syncPayload()
	if err != nil {
		return res, err
	}
	enc, err := encryptSyncPayload(plain, norm.SyncPassword)
	if err != nil {
		return res, err
	}
	if err := client.Write(norm.RemotePath, enc, 0o644); err != nil {
		return res, wrapWebDAVErr("上传同步文件", err)
	}
	res.Pushed = true
	return res, nil
}

// syncPayload 返回 entries+墓碑 的 JSON 明文（加锁快照）。
func (v *Vault) syncPayload() ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return nil, ErrVaultLocked
	}
	return json.Marshal(vaultPayload{Entries: v.entries, Deleted: v.deleted})
}

// encryptSyncPayload 用同步密码 + 独立随机盐加密同步明文，输出完整 .enc 文件镜像。
func encryptSyncPayload(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	blob, err := encryptBlob(plaintext, key, salt)
	if err != nil {
		return nil, err
	}
	// 擦除派生密钥副本
	for i := range key {
		key[i] = 0
	}
	return blob, nil
}

// wrapWebDAVErr 将常见 HTTP 状态码翻译为可操作的中文错误。
func wrapWebDAVErr(op string, err error) error {
	switch {
	case gowebdav.IsErrCode(err, 401):
		return errors.New("WebDAV 认证失败，请检查账号与应用密码")
	case gowebdav.IsErrCode(err, 403):
		return errors.New("WebDAV 拒绝访问（权限不足或应用密码未授权该操作）")
	case gowebdav.IsErrCode(err, 404):
		return errors.New(op + "失败：远端路径不存在")
	case gowebdav.IsErrCode(err, 507):
		return errors.New(op + "失败：网盘空间不足")
	}
	return fmt.Errorf("%s失败: %w", op, err)
}
