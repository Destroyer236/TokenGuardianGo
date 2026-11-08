//go:build windows

// quickunlock_windows.go 实现基于 Windows Hello 的默认快速解锁（零操作）。
//
// 设计（与 Bitwarden 等"用 Windows Hello 解锁"的密码管理器同款思路）：
//   1. 自动准备：主密码验证成功（解锁/创建保险库）后，自动将 Argon2id 派生
//      密钥存入 Windows 凭据管理器（密码本身已验证身份，无需弹窗）；
//   2. 自动解锁：解锁门出现时自动弹出系统 Hello 验证窗口，手指一按即进；
//      取消弹窗或本机未配置 Hello 时回退主密码输入，主密码始终保留为兜底。
//
// 系统选择：直接调用 WinBio（生物识别框架）在 Goodix 等消费级传感器上拿不到
// 捕获（系统池被 Windows Hello 登录组件独占，实测会话打开但手指无反应），
// 因此改走 Hello 同意路径（UserConsentVerifier，即 UAC/"Windows Hello 确认"
// 同款系统窗口，必然可见），经 winhello-go（MIT）调用。
//
// 安全边界（须向用户说明）：
//   - 指纹本身不参与加密，只是"确认是本人"的系统级同意门；
//   - 派生密钥由凭据管理器按 Windows 用户隔离，但同一用户会话内的其他进程
//     理论上可直接读取（行业同类实现的共同局限）；
//   - 保险库被删除重置后，存储的派生密钥自动失效并在下次快速解锁时清除。
package core

import (
	"errors"
	"fmt"

	winhello "github.com/julian-bruyers/winhello-go"

	"github.com/danieljoos/wincred"
)

// quickUnlockCredName 是派生密钥在 Windows 凭据管理器中的条目名。
const quickUnlockCredName = "Authenticator_QuickUnlock"

// 業務错误（文案与前端 UI 对齐）。
var (
	ErrQuickUnlockUnavailable = errors.New("此设备未配置 Windows Hello，指纹解锁不可用")
	ErrQuickUnlockCanceled    = errors.New("已取消指纹验证")
	ErrQuickUnlockFailed      = errors.New("指纹验证未通过")
	ErrQuickUnlockStale       = errors.New("指纹解锁凭据已失效，请用主密码解锁后重新生效")
)

// windowsHelloVerify 弹出系统 Windows Hello 验证窗口（用户配置的指纹/人脸/PIN，
// 由系统绘制、必然可见），验证通过后返回 nil。
func windowsHelloVerify(prompt string) error {
	ok, err := winhello.Authenticate(prompt)
	if err != nil {
		switch {
		case errors.Is(err, winhello.ErrNotAvailable):
			return ErrQuickUnlockUnavailable
		case errors.Is(err, winhello.ErrUserCanceled):
			return ErrQuickUnlockCanceled
		}
		return fmt.Errorf("Windows Hello 验证失败: %w", err)
	}
	if !ok {
		return ErrQuickUnlockFailed
	}
	return nil
}

// FingerprintUnlockAvailable 解锁门是否应自动弹出 Hello 验证：
// 本机已配置 Windows Hello 且本地已存有快速解锁凭据。
func FingerprintUnlockAvailable() bool {
	if !winhello.Available() {
		return false
	}
	_, err := wincred.GetGenericCredential(quickUnlockCredName)
	return err == nil
}

// EnsureQuickUnlock 在主密码验证成功后自动准备快速解锁：
// 将 Argon2id 派生密钥存入 Windows 凭据管理器（密码本身已验证身份，
// 无需再次弹窗）。本机未配置 Windows Hello 时静默跳过。
// 保险库每次用主密码成功解锁/创建后调用，保持存储密钥始终有效。
func EnsureQuickUnlock(v *Vault) error {
	if !winhello.Available() {
		return nil
	}
	key, err := v.KeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	cred := wincred.NewGenericCredential(quickUnlockCredName)
	cred.CredentialBlob = key
	cred.Persist = wincred.PersistLocalMachine
	return cred.Write()
}

// RemoveQuickUnlock 删除存储的快速解锁凭据（保险库重置等场景的自愈清理）。
func RemoveQuickUnlock() error {
	cred := wincred.NewGenericCredential(quickUnlockCredName)
	return cred.Delete()
}

// QuickUnlock 弹出系统 Hello 验证，通过后从凭据管理器取出派生密钥并打开保险库。
// 保险库已被删除/重置导致密钥失效时，自动清除过期凭据并返回 ErrQuickUnlockStale。
func QuickUnlock(path string) (*Vault, error) {
	if err := windowsHelloVerify("验证身份以解锁保险库"); err != nil {
		return nil, err
	}
	cred, err := wincred.GetGenericCredential(quickUnlockCredName)
	if err != nil {
		// 凭据不存在（被手动清除等）→ 视为失效，下次主密码解锁后自动重建
		return nil, ErrQuickUnlockStale
	}
	key := append([]byte(nil), cred.CredentialBlob...)
	defer zeroBytes(key)
	v, err := OpenWithKey(path, key)
	if err != nil {
		// 密钥失效（保险库重置/更换）→ 清除过期凭据，避免长期残留
		_ = RemoveQuickUnlock()
		return nil, fmt.Errorf("%w（%v）", ErrQuickUnlockStale, err)
	}
	return v, nil
}

// zeroBytes 用后清零敏感字节切片。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
