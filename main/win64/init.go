package win64

import (
	"syscall"
	"unsafe"
)

func init() {
	is64bit := unsafe.Sizeof(uintptr(0)) == 8
	if is64bit {
		INVALID_HANDLE_VALUE = 0xffffffffffffffff
	} else {
		INVALID_HANDLE_VALUE = 0xffffffff
	}

	libkernel32 = syscall.NewLazyDLL("kernel32.dll")
	libuser32 = syscall.NewLazyDLL("user32.dll")

	procCloseHandle = libkernel32.NewProc("CloseHandle")
	procCreateFileA = libkernel32.NewProc("CreateFileA")
	procCreateFileW = libkernel32.NewProc("CreateFileW")
	procCreateRemoteThread = libkernel32.NewProc("CreateRemoteThread")
	procCreateToolhelp32Snapshot = libkernel32.NewProc("CreateToolhelp32Snapshot")
	procFindClose = libkernel32.NewProc("FindClose")
	procFindFirstFileA = libkernel32.NewProc("FindFirstFileA")
	procFindFirstFileW = libkernel32.NewProc("FindFirstFileW")
	procFindNextFileA = libkernel32.NewProc("FindNextFileA")
	procFindNextFileW = libkernel32.NewProc("FindNextFileW")
	procFreeLibrary = libkernel32.NewProc("FreeLibrary")
	procGetCurrentProcessId = libkernel32.NewProc("GetCurrentProcessId")
	procGetModuleHandleA = libkernel32.NewProc("GetModuleHandleA")
	procGetModuleHandleW = libkernel32.NewProc("LoadLibraryW")
	procGetNamedPipeClientProcessId = libkernel32.NewProc("GetNamedPipeClientProcessId")
	procGetProcAddress = libkernel32.NewProc("GetProcAddress")
	procLoadLibraryA = libkernel32.NewProc("LoadLibraryA")
	procLoadLibraryW = libkernel32.NewProc("LoadLibraryW")
	procMessageBoxA = libuser32.NewProc("MessageBoxA")
	procMessageBoxW = libuser32.NewProc("MessageBoxW")
	procModule32FirstW = libkernel32.NewProc("Module32FirstW")
	procModule32NextW = libkernel32.NewProc("Module32NextW")
	procOpenProcess = libkernel32.NewProc("OpenProcess")
	procProcess32FirstW = libkernel32.NewProc("Process32FirstW")
	procProcess32NextW = libkernel32.NewProc("Process32NextW")
	procReadFile = libkernel32.NewProc("ReadFile")
	procReadProcessMemory = libkernel32.NewProc("ReadProcessMemory")
	procEnumWindows = libuser32.NewProc("EnumWindows")
	procIsWindowVisible = libuser32.NewProc("IsWindowVisible")
	procGetWindow = libuser32.NewProc("GetWindow")
	procGetWindowThreadProcessId = libuser32.NewProc("GetWindowThreadProcessId")
	procSetForegroundWindow = libuser32.NewProc("SetForegroundWindow")
	procSetWindowPos = libuser32.NewProc("SetWindowPos")
	procShowWindow = libuser32.NewProc("ShowWindow")
	procVirtualAllocEx = libkernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx = libkernel32.NewProc("VirtualFreeEx")
	procWaitForSingleObject = libkernel32.NewProc("WaitForSingleObject")
	procWriteFile = libkernel32.NewProc("WriteFile")
	procWriteProcessMemory = libkernel32.NewProc("WriteProcessMemory")
}
