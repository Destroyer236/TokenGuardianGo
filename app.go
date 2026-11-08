package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"authenticator/core"
)

// App 是暴露给前端的 Wails 绑定层。
type App struct {
	ctx       context.Context
	vault     *core.Vault
	mu        sync.Mutex
	vaultPath string

	// WebDAV 同步状态
	syncMu       sync.Mutex  // 串行化所有同步（含网络 IO；刻意不与 mu 互锁，避免 15s 超时卡住 UI 绑定）
	autoMu       sync.Mutex  // 保护 autoTimer
	autoTimer    *time.Timer // 数据变更后的防抖自动同步
	syncCfgPath  string      // webdav.enc 路径
	lastSyncMu   sync.Mutex
	lastSyncAt   time.Time // 最近一次同步（成功或失败）时刻
	lastSyncText string    // 最近一次成功同步的人类可读摘要
	lastSyncErr  string    // 最近一次同步失败原因
}

// EntryInfo 列表项（不暴露密钥本体）。
type EntryInfo struct {
	Name      string `json:"name"`
	Algo      string `json:"algo"`
	Counter   uint64 `json:"counter"`
	UpdatedAt string `json:"updatedAt"`
}

// EntryFull 完整条目（编辑对话框需要密钥本体）。
type EntryFull struct {
	EntryInfo
	Secret string `json:"secret"`
}

// CodeInfo 快照中的一条验证码。
type CodeInfo struct {
	Name             string `json:"name"`
	Algo             string `json:"algo"`
	Code             string `json:"code"`
	SecondsRemaining int    `json:"secondsRemaining"` // HOTP 为 -1
	Counter          uint64 `json:"counter"`
	Error            string `json:"error,omitempty"`
}

func NewApp() *App {
	return &App{}
}

// startup 由 Wails 调用：保存运行时上下文并确定默认保险库路径。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if path, err := core.DefaultVaultPath(); err == nil {
		a.vaultPath = path
		a.syncCfgPath = core.SyncConfigPath(path)
	}
}

// requireVault 返回已解锁的保险库（带锁保护）。
func (a *App) requireVault() (*core.Vault, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.vault == nil {
		return nil, core.ErrVaultLocked
	}
	return a.vault, nil
}

// ---------- 生命周期 ----------

// VaultExists 判断默认路径是否已有保险库（决定首启是"设置密码"还是"解锁"）。
func (a *App) VaultExists() bool {
	return core.VaultFileExists(a.vaultPath)
}

// SetPassword 首次使用：创建保险库并直接解锁。
func (a *App) SetPassword(password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.vault != nil {
		return errors.New("保险库已解锁")
	}
	v, err := core.Create(a.vaultPath, password)
	if err != nil {
		return err
	}
	a.vault = v
	_ = core.EnsureQuickUnlock(v) // 自动准备指纹快速解锁（失败不影响主流程）
	return nil
}

// Unlock 用主密码解锁保险库。
func (a *App) Unlock(password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.vault != nil {
		return nil
	}
	v, err := core.Open(a.vaultPath, password)
	if err != nil {
		return err
	}
	a.vault = v
	_ = core.EnsureQuickUnlock(v) // 自动准备指纹快速解锁（失败不影响主流程）
	return nil
}

// Lock 锁定保险库并清空内存密钥。
func (a *App) Lock() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.vault != nil {
		a.vault.Close()
		a.vault = nil
	}
	a.autoMu.Lock()
	if a.autoTimer != nil {
		a.autoTimer.Stop()
		a.autoTimer = nil
	}
	a.autoMu.Unlock()
}

// IsUnlocked 返回解锁状态。
func (a *App) IsUnlocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.vault != nil
}

// ---------- 密钥管理 ----------

// ListSecrets 返回全部密钥（不含密钥本体）。
func (a *App) ListSecrets() ([]EntryInfo, error) {
	v, err := a.requireVault()
	if err != nil {
		return nil, err
	}
	entries := v.Entries()
	out := make([]EntryInfo, len(entries))
	for i, e := range entries {
		out[i] = EntryInfo{Name: e.Name, Algo: e.Algo, Counter: e.Counter, UpdatedAt: e.UpdatedAt.Format("2006-01-02 15:04")}
	}
	return out, nil
}

// GetEntry 返回单条完整条目（编辑用）。
func (a *App) GetEntry(name string) (EntryFull, error) {
	v, err := a.requireVault()
	if err != nil {
		return EntryFull{}, err
	}
	e, err := v.Get(name)
	if err != nil {
		return EntryFull{}, err
	}
	return EntryFull{
		EntryInfo: EntryInfo{Name: e.Name, Algo: e.Algo, Counter: e.Counter, UpdatedAt: e.UpdatedAt.Format("2006-01-02 15:04")},
		Secret:    e.Secret,
	}, nil
}

// AddSecret 新增密钥。
func (a *App) AddSecret(name, secret, algo string, counter uint64) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	if err := v.Add(name, secret, algo, counter); err != nil {
		return err
	}
	a.scheduleAutoSync()
	return nil
}

// RemoveSecret 删除密钥。
func (a *App) RemoveSecret(name string) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	if err := v.Remove(name); err != nil {
		return err
	}
	a.scheduleAutoSync()
	return nil
}

// UpdateSecret 修改密钥。
func (a *App) UpdateSecret(oldName, newName, secret, algo string, counter uint64) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	if err := v.Update(oldName, newName, secret, algo, counter); err != nil {
		return err
	}
	a.scheduleAutoSync()
	return nil
}

// NextHOTP 递增 HOTP 计数器并返回新验证码。
func (a *App) NextHOTP(name string) (CodeInfo, error) {
	v, err := a.requireVault()
	if err != nil {
		return CodeInfo{}, err
	}
	counter, err := v.IncrementCounter(name)
	if err != nil {
		return CodeInfo{}, err
	}
	a.scheduleAutoSync()
	e, err := v.Get(name)
	if err != nil {
		return CodeInfo{}, err
	}
	info := CodeInfo{Name: name, Algo: e.Algo, Counter: counter, SecondsRemaining: -1}
	code, err := core.GenerateHOTP(e.Secret, counter)
	if err != nil {
		info.Error = "无效密钥"
	} else {
		info.Code = code
	}
	return info, nil
}

// ---------- 验证码快照 ----------

// nowFunc 可替换的时间源（测试钩子）。
var nowFunc = time.Now

// GetSnapshot 计算全部密钥的当前验证码（TOTP 含剩余秒数，HOTP 含计数器）。
// 前端每秒轮询一次。
func (a *App) GetSnapshot() []CodeInfo {
	v, err := a.requireVault()
	if err != nil {
		return nil
	}
	entries := v.Entries()
	now := nowFunc()
	out := make([]CodeInfo, len(entries))
	for i, e := range entries {
		info := CodeInfo{Name: e.Name, Algo: e.Algo, Counter: e.Counter}
		if e.Algo == core.AlgoHOTP {
			info.SecondsRemaining = -1
			code, err := core.GenerateHOTP(e.Secret, e.Counter)
			if err != nil {
				info.Error = "无效密钥"
			} else {
				info.Code = code
			}
		} else {
			info.SecondsRemaining = core.SecondsRemaining(core.DefaultInterval, now)
			code, err := core.GenerateTOTP(e.Secret, core.DefaultInterval, now)
			if err != nil {
				info.Error = "无效密钥"
			} else {
				info.Code = code
			}
		}
		out[i] = info
	}
	return out
}

// ---------- 导入 / 导出 ----------

// ExportVault 导出全部密钥到指定加密文件（独立密码）。
func (a *App) ExportVault(path, password string) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	return v.ExportEntries(nil, path, password)
}

// ExportSingle 导出单条密钥到指定加密文件（独立密码）。
func (a *App) ExportSingle(name, path, password string) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	e, err := v.Get(name)
	if err != nil {
		return err
	}
	return v.ExportEntries([]core.Entry{e}, path, password)
}

// ImportVault 从加密文件导入密钥，返回导入条数。
func (a *App) ImportVault(path, password string) (int, error) {
	v, err := a.requireVault()
	if err != nil {
		return 0, err
	}
	n, err := v.Import(path, password)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		a.scheduleAutoSync()
	}
	return n, nil
}

// ---------- WebDAV 同步 ----------

// SyncSettingsInfo 同步配置概要（不回传任何密码）。
type SyncSettingsInfo struct {
	Configured    bool   `json:"configured"`
	ServerURL     string `json:"serverUrl"`
	Username      string `json:"username"`
	RemotePath    string `json:"remotePath"`
	LastSyncAt    string `json:"lastSyncAt"`             // 最近同步时刻 "2006-01-02 15:04"，空 = 从未
	LastSyncText  string `json:"lastSyncText"`           // 最近一次成功同步摘要，空 = 尚未同步
	LastSyncError string `json:"lastSyncError,omitempty"` // 最近一次同步失败原因
}

// GetSyncSettings 返回当前同步配置与最近同步状态。
func (a *App) GetSyncSettings() SyncSettingsInfo {
	info := SyncSettingsInfo{}
	a.lastSyncMu.Lock()
	if !a.lastSyncAt.IsZero() {
		info.LastSyncAt = a.lastSyncAt.Format("2006-01-02 15:04")
	}
	info.LastSyncText, info.LastSyncError = a.lastSyncText, a.lastSyncErr
	a.lastSyncMu.Unlock()

	v, err := a.requireVault()
	if err != nil {
		return info
	}
	cfg, err := core.LoadSyncConfig(a.syncCfgPath, v)
	if err != nil {
		info.LastSyncError = err.Error()
		return info
	}
	if cfg == nil {
		return info
	}
	info.Configured = true
	info.ServerURL = cfg.ServerURL
	info.Username = cfg.Username
	info.RemotePath = cfg.RemotePath
	return info
}

// SaveSyncSettings 校验连通性后保存同步配置。
// 两个密码参数传空表示沿用已保存的值（修改服务器地址时不必重输密码）。
func (a *App) SaveSyncSettings(serverURL, username, webdavPassword, remotePath, syncPassword string) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	old, err := core.LoadSyncConfig(a.syncCfgPath, v)
	if err != nil {
		return err
	}
	if webdavPassword == "" && old != nil {
		webdavPassword = old.WebDAVPassword
	}
	if syncPassword == "" && old != nil {
		syncPassword = old.SyncPassword
	}
	cfg := &core.SyncConfig{
		ServerURL:      serverURL,
		Username:       username,
		WebDAVPassword: webdavPassword,
		SyncPassword:   syncPassword,
		RemotePath:     remotePath,
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	// 保存前先验证连通性与认证，避免存下不可用配置
	if err := core.TestSyncConnection(cfg.ServerURL, cfg.Username, cfg.WebDAVPassword); err != nil {
		return err
	}
	return core.SaveSyncConfig(a.syncCfgPath, v, cfg)
}

// TestSyncConnection 测试 WebDAV 连通性；应用密码传空时用已保存的值。
func (a *App) TestSyncConnection(serverURL, username, webdavPassword string) error {
	if webdavPassword == "" {
		v, err := a.requireVault()
		if err == nil {
			if old, err := core.LoadSyncConfig(a.syncCfgPath, v); err == nil && old != nil {
				webdavPassword = old.WebDAVPassword
			}
		}
	}
	return core.TestSyncConnection(serverURL, username, webdavPassword)
}

// SyncNow 立即执行一次手动同步。
func (a *App) SyncNow() (core.SyncResult, error) {
	return a.runSync(false)
}

// GetSyncRemoteInfo 查询远端同步文件的元信息（存在性 / 大小 / 服务器端修改时间）。
func (a *App) GetSyncRemoteInfo() (core.RemoteFileInfo, error) {
	v, err := a.requireVault()
	if err != nil {
		return core.RemoteFileInfo{}, err
	}
	cfg, err := core.LoadSyncConfig(a.syncCfgPath, v)
	if err != nil {
		return core.RemoteFileInfo{}, err
	}
	if cfg == nil {
		return core.RemoteFileInfo{}, errors.New("尚未配置 WebDAV 同步")
	}
	return core.StatRemote(v, cfg)
}

// DisableSync 停用同步：删除本地同步配置文件（webdav.enc）。云端文件不受影响。
func (a *App) DisableSync() error {
	if _, err := a.requireVault(); err != nil {
		return err
	}
	if err := os.Remove(a.syncCfgPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	a.lastSyncMu.Lock()
	a.lastSyncAt = time.Time{}
	a.lastSyncText = ""
	a.lastSyncErr = ""
	a.lastSyncMu.Unlock()
	return nil
}

// runSync 执行一次同步（手动或自动）并记录结果。
func (a *App) runSync(auto bool) (core.SyncResult, error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	v, err := a.requireVault()
	if err != nil {
		a.recordSync(core.SyncResult{}, err)
		return core.SyncResult{}, err
	}
	cfg, err := core.LoadSyncConfig(a.syncCfgPath, v)
	if err != nil {
		a.recordSync(core.SyncResult{}, err)
		return core.SyncResult{}, err
	}
	if cfg == nil {
		err = errors.New("尚未配置 WebDAV 同步")
		a.recordSync(core.SyncResult{}, err)
		return core.SyncResult{}, err
	}
	res, err := core.DoSync(v, cfg)
	a.recordSync(res, err)
	return res, err
}

// recordSync 记录最近一次同步结果（供详情与设置界面展示）。
func (a *App) recordSync(res core.SyncResult, err error) {
	a.lastSyncMu.Lock()
	defer a.lastSyncMu.Unlock()
	a.lastSyncAt = time.Now()
	if err != nil {
		a.lastSyncErr = err.Error()
		a.lastSyncText = ""
		return
	}
	a.lastSyncErr = ""
	var parts []string
	if res.Added > 0 {
		parts = append(parts, fmt.Sprintf("新增 %d", res.Added))
	}
	if res.Updated > 0 {
		parts = append(parts, fmt.Sprintf("更新 %d", res.Updated))
	}
	if res.Deleted > 0 {
		parts = append(parts, fmt.Sprintf("删除 %d", res.Deleted))
	}
	if len(parts) == 0 {
		a.lastSyncText = "已与云端一致"
	} else {
		a.lastSyncText = strings.Join(parts, " · ")
	}
}

// scheduleAutoSync 在数据变更后防抖触发一次后台静默同步（失败仅记录，不打扰用户）。
func (a *App) scheduleAutoSync() {
	a.autoMu.Lock()
	defer a.autoMu.Unlock()
	if a.autoTimer != nil {
		a.autoTimer.Stop()
	}
	a.autoTimer = time.AfterFunc(2500*time.Millisecond, func() {
		_, _ = a.runSync(true)
	})
}

// ---------- 指纹快速解锁（Windows Hello，默认自动） ----------

// FingerprintUnlockAvailable 解锁门是否应自动弹出 Hello 验证：
// 保险库已存在 + 本机已配置 Windows Hello + 快速解锁凭据已就绪。
func (a *App) FingerprintUnlockAvailable() bool {
	if a.vaultPath == "" || !core.VaultFileExists(a.vaultPath) {
		return false
	}
	return core.FingerprintUnlockAvailable()
}

// QuickUnlock 解锁门：弹出系统 Hello 验证，通过后用存储的派生密钥直接开保险库。
// 验证期间不持有 a.mu（系统弹窗可能停留任意久），解锁成功后再落状态。
func (a *App) QuickUnlock() error {
	a.mu.Lock()
	already := a.vault != nil
	a.mu.Unlock()
	if already {
		return nil // 已解锁
	}
	v, err := core.QuickUnlock(a.vaultPath)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.vault = v
	return nil
}

// PickSaveFile 弹出系统"保存文件"对话框，返回所选路径（取消时为空串）。
func (a *App) PickSaveFile(title, defaultFilename string) string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           title,
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: "Authenticator 加密文件 (*.enc)", Pattern: "*.enc"},
		},
	})
	if err != nil {
		return ""
	}
	return path
}

// PickOpenFile 弹出系统"打开文件"对话框，返回所选路径（取消时为空串）。
func (a *App) PickOpenFile(title string) string {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: title,
		Filters: []runtime.FileFilter{
			{DisplayName: "Authenticator 加密文件 (*.enc)", Pattern: "*.enc"},
		},
	})
	if err != nil {
		return ""
	}
	return path
}
