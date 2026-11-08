//go:build !windows

package core

// markHidden 非 Windows 平台为空操作（保持 API 一致，文件不做隐藏）。
func markHidden(path string) error { return nil }
