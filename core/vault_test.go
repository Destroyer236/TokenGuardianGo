package core

import (
	"os"
	"path/filepath"
	"testing"
)

const vaultPwd = "test-密码-123"

func newTestVault(t *testing.T, dir string) *Vault {
	t.Helper()
	path := filepath.Join(dir, "vault.enc")
	v, err := Create(path, vaultPwd)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return v
}

// TestVaultRoundTrip 增删改查后重新打开，数据必须一致（覆盖"保存后重开"的盐一致性）。
func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := newTestVault(t, dir)
	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatalf("Add TOTP: %v", err)
	}
	if err := v.Add("Steam", testSecret, AlgoHOTP, 5); err != nil {
		t.Fatalf("Add HOTP: %v", err)
	}
	if err := v.Update("GitHub", "GitLab", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatalf("Update: %v", err)
	}
	newCounter, err := v.IncrementCounter("Steam")
	if err != nil || newCounter != 6 {
		t.Fatalf("IncrementCounter = %d, err=%v, 期望 6", newCounter, err)
	}
	v.Close()

	v2, err := Open(path, vaultPwd)
	if err != nil {
		t.Fatalf("重开保险库失败（盐一致性）: %v", err)
	}
	defer v2.Close()

	if got := len(v2.Entries()); got != 2 {
		t.Fatalf("条目数 = %d, 期望 2", got)
	}
	e, err := v2.Get("GitLab")
	if err != nil || e.Algo != AlgoTOTP || e.Secret != testSecret {
		t.Errorf("GitLab 条目不符: %+v, err=%v", e, err)
	}
	e, err = v2.Get("Steam")
	if err != nil || e.Algo != AlgoHOTP || e.Counter != 6 {
		t.Errorf("Steam 条目不符: %+v, err=%v", e, err)
	}
}

// TestVaultWrongPassword 错误密码必须被拒绝；正确密码可重新打开。
func TestVaultWrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := newTestVault(t, dir)
	v.Close()

	if _, err := Open(path, "wrong-password"); err != ErrWrongPassword {
		t.Fatalf("错误密码应返回 ErrWrongPassword, got %v", err)
	}
	if _, err := Open(path, vaultPwd); err != nil {
		t.Fatalf("正确密码应能打开: %v", err)
	}
}

// TestVaultDuplicateName 重名密钥必须被拒绝。
func TestVaultDuplicateName(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	if err := v.Add("A", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatalf("首次 Add: %v", err)
	}
	if err := v.Add("A", testSecret, AlgoTOTP, 0); err != ErrNameExists {
		t.Fatalf("重名应返回 ErrNameExists, got %v", err)
	}
}

// TestVaultValidation 名称为空 / 非法密钥 / 非法算法必须被拒绝。
func TestVaultValidation(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	if err := v.Add("", testSecret, AlgoTOTP, 0); err == nil {
		t.Error("空名称应报错")
	}
	if err := v.Add("X", "not@base32!!", AlgoTOTP, 0); err == nil {
		t.Error("非法 Base32 应报错")
	}
	if err := v.Add("X", testSecret, "MD5", 0); err != ErrBadAlgo {
		t.Error("非法算法应报错")
	}
}

// TestVaultTamper 篡改密文后打开必须失败（GCM 认证加密）。
func TestVaultTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := newTestVault(t, dir)
	v.Close()

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xFF // 翻转密文最后一字节
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, vaultPwd); err == nil {
		t.Fatal("篡改后的文件应无法解密")
	}
}

// TestVaultExportImport 导出 → 新库导入必须还原数据；重名导入跳过。
func TestVaultExportImport(t *testing.T) {
	dir := t.TempDir()
	exportFile := filepath.Join(dir, "backup.enc")

	v := newTestVault(t, dir)
	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Add("Steam", testSecret, AlgoHOTP, 5); err != nil {
		t.Fatal(err)
	}
	if err := v.ExportEntries(nil, exportFile, "export-pwd"); err != nil {
		t.Fatalf("ExportEntries: %v", err)
	}
	v.Close()

	// 新库导入
	v2, err := Create(filepath.Join(dir, "restored.enc"), "new-pwd")
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()

	n, err := v2.Import(exportFile, "export-pwd")
	if err != nil || n != 2 {
		t.Fatalf("Import = %d, err=%v, 期望 2", n, err)
	}
	if _, err := v2.Get("Steam"); err != nil {
		t.Errorf("导入后应能找到 Steam: %v", err)
	}

	// 再次导入：全部重名跳过
	n, err = v2.Import(exportFile, "export-pwd")
	if err != nil || n != 0 {
		t.Fatalf("重复导入应跳过全部条目, got %d, err=%v", n, err)
	}

	// 导出密码错误
	if _, err := v2.Import(exportFile, "wrong"); err != ErrWrongPassword {
		t.Fatalf("导入密码错误应返回 ErrWrongPassword, got %v", err)
	}
}

// TestVaultExportSingle 只导出单条。
func TestVaultExportSingle(t *testing.T) {
	dir := t.TempDir()
	exportFile := filepath.Join(dir, "single.enc")

	v := newTestVault(t, dir)
	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Add("Steam", testSecret, AlgoHOTP, 0); err != nil {
		t.Fatal(err)
	}
	e, _ := v.Get("Steam")
	if err := v.ExportEntries([]Entry{e}, exportFile, "p"); err != nil {
		t.Fatal(err)
	}
	v.Close()

	v2, err := Create(filepath.Join(dir, "restored.enc"), "p2")
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	n, err := v2.Import(exportFile, "p")
	if err != nil || n != 1 {
		t.Fatalf("单条导入 = %d, err=%v, 期望 1", n, err)
	}
	if _, err := v2.Get("GitHub"); err == nil {
		t.Error("不应导入未选择的 GitHub")
	}
}

// TestCreateExistingVault 已存在的保险库不能被 Create 覆盖。
func TestCreateExistingVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v, err := Create(path, vaultPwd)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	if _, err := Create(path, "other"); err != ErrVaultExists {
		t.Fatalf("重复创建应返回 ErrVaultExists, got %v", err)
	}
}
