//go:build !windows

// quickunlock_other.go 非 Windows 平台的快速解锁桩（保持 API 一致，功能不可用）。
package core

import "errors"

var ErrQuickUnlockUnavailable = errors.New("指纹解锁仅支持 Windows")

// FingerprintUnlockAvailable 非 Windows 平台恒为 false。
func FingerprintUnlockAvailable() bool { return false }

// EnsureQuickUnlock 非 Windows 平台无操作。
func EnsureQuickUnlock(v *Vault) error { return nil }

// RemoveQuickUnlock 非 Windows 平台无操作。
func RemoveQuickUnlock() error { return nil }

// QuickUnlock 非 Windows 平台不可用。
func QuickUnlock(path string) (*Vault, error) { return nil, ErrQuickUnlockUnavailable }
