//go:build windows

package core

import "golang.org/x/sys/windows"

// markHidden 在 Windows 上为保险库文件设置系统隐藏属性
// （资源管理器默认不显示，防误删；删除它即可重置主密码）。
func markHidden(path string) error {
	return windows.SetFileAttributes(windows.StringToUTF16Ptr(path), windows.FILE_ATTRIBUTE_HIDDEN)
}
