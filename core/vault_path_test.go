package core

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultVaultPathNextToExecutable 保险库默认路径必须位于程序所在目录（便携式设计）。
func TestDefaultVaultPathNextToExecutable(t *testing.T) {
	path, err := DefaultVaultPath()
	if err != nil {
		t.Fatalf("DefaultVaultPath: %v", err)
	}
	if filepath.Base(path) != "vault.enc" {
		t.Errorf("文件名 = %q, 期望 vault.enc", filepath.Base(path))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip("无法获取可执行文件路径")
	}
	if dir := filepath.Dir(path); dir != filepath.Dir(exe) {
		t.Errorf("保险库目录 = %q, 期望程序目录 %q", dir, filepath.Dir(exe))
	}
}
