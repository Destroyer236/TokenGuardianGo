package core

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestVaultOpenWithKey 指纹快速解锁的密钥直开路径：正确密钥秒开，错误密钥拒绝。
func TestVaultOpenWithKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := newTestVault(t, dir)
	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	key, err := v.KeyCopy()
	if err != nil {
		t.Fatalf("KeyCopy: %v", err)
	}
	if len(key) != keySize {
		t.Fatalf("KeyCopy 长度 = %d, 期望 %d", len(key), keySize)
	}
	v.Close()

	// 锁定后 KeyCopy 必须拒绝
	if _, err := v.KeyCopy(); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("未解锁时 KeyCopy 应返回 ErrVaultLocked, got %v", err)
	}

	// 正确密钥直接打开（跳过 Argon2），数据完整
	v2, err := OpenWithKey(path, key)
	if err != nil {
		t.Fatalf("OpenWithKey: %v", err)
	}
	defer v2.Close()
	e, err := v2.Get("GitHub")
	if err != nil || e.Secret != testSecret {
		t.Fatalf("OpenWithKey 后数据不符: %+v, %v", e, err)
	}

	// 用打开后的保险库继续写入 → 与密码解锁的实例等效
	if err := v2.Add("Steam", testSecret, AlgoHOTP, 1); err != nil {
		t.Fatalf("OpenWithKey 后写入失败: %v", err)
	}
	v2.Close()

	v3, err := Open(path, vaultPwd)
	if err != nil {
		t.Fatalf("主密码应仍能打开: %v", err)
	}
	defer v3.Close()
	if _, err := v3.Get("Steam"); err != nil {
		t.Fatalf("OpenWithKey 写入的数据应持久化: %v", err)
	}

	// 错误密钥必须被拒绝
	wrong := make([]byte, keySize)
	for i := range wrong {
		wrong[i] = 0xAA
	}
	if _, err := OpenWithKey(path, wrong); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("错误密钥应返回 ErrWrongPassword, got %v", err)
	}

	// 不存在的文件
	if _, err := OpenWithKey(filepath.Join(dir, "missing.enc"), key); err == nil {
		t.Fatal("不存在的文件应报错")
	}
}
