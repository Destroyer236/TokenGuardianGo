package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"TokenGuardianGo/core"
)

// App 是暴露给前端的 Wails 绑定层。
type App struct {
	ctx       context.Context
	vault     *core.Vault
	mu        sync.Mutex
	vaultPath string
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
	return v.Add(name, secret, algo, counter)
}

// RemoveSecret 删除密钥。
func (a *App) RemoveSecret(name string) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	return v.Remove(name)
}

// UpdateSecret 修改密钥。
func (a *App) UpdateSecret(oldName, newName, secret, algo string, counter uint64) error {
	v, err := a.requireVault()
	if err != nil {
		return err
	}
	return v.Update(oldName, newName, secret, algo, counter)
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
	return v.Import(path, password)
}

// PickSaveFile 弹出系统"保存文件"对话框，返回所选路径（取消时为空串）。
func (a *App) PickSaveFile(title, defaultFilename string) string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           title,
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: "TokenGuardian 加密文件 (*.enc)", Pattern: "*.enc"},
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
			{DisplayName: "TokenGuardian 加密文件 (*.enc)", Pattern: "*.enc"},
		},
	})
	if err != nil {
		return ""
	}
	return path
}
