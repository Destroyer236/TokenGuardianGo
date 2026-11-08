//go:build windows

package core

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestMarkHidden 标记后的文件必须带系统隐藏属性。
func TestMarkHidden(t *testing.T) {
	f := filepath.Join(t.TempDir(), "probe.enc")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := markHidden(f); err != nil {
		t.Fatalf("markHidden: %v", err)
	}
	attr, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(f))
	if err != nil {
		t.Fatal(err)
	}
	if attr&windows.FILE_ATTRIBUTE_HIDDEN == 0 {
		t.Fatal("文件未带隐藏属性")
	}
}

// TestVaultFileStaysHidden 创建与多次原子保存后，保险库必须始终保持隐藏属性。
func TestVaultFileStaysHidden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.enc")
	v, err := Create(path, "pwd-123")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	check := func(stage string) {
		t.Helper()
		attr, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if attr&windows.FILE_ATTRIBUTE_HIDDEN == 0 {
			t.Fatalf("%s: 保险库丢失隐藏属性", stage)
		}
	}
	check("创建后")
	if err := v.Add("A", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	check("原子替换保存后")
	if err := v.Add("B", testSecret, AlgoHOTP, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := v.IncrementCounter("B"); err != nil {
		t.Fatal(err)
	}
	check("HOTP 计数保存后")
}
