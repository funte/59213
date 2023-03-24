package main

import (
	"errors"
	"fmt"
	"main/win64"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	libkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procFreeLibrary  = libkernel32.NewProc("FreeLibrary")
	procLoadLibraryW = libkernel32.NewProc("LoadLibraryW")
)

func InjectDLL(pid uint32, modulePath string) error {
	if hProcess, err := win64.OpenProcess(
		win64.PROCESS_ALL_ACCESS, false, pid,
	); err != nil {
		return err
	} else {
		defer win64.CloseHandle(hProcess)

		// Alloc remote buffer.
		if len(modulePath) > syscall.MAX_PATH {
			return errors.New("Path too long")
		}
		size := uint((len(modulePath) + 1) * 2)
		if remoteModulePath, err := win64.VirtualAllocEx(
			hProcess, 0, size, win64.MEM_COMMIT, win64.PAGE_READWRITE,
		); err != nil {
			return err
		} else {
			// Write module path to remote buffer.
			utf16s := syscall.StringToUTF16(modulePath)
			if err := win64.WriteProcessMemory(
				hProcess,
				remoteModulePath, uintptr(unsafe.Pointer(&utf16s[0])),
				size, nil,
			); err != nil {
				return err
			}
			defer win64.VirtualFreeEx(hProcess, remoteModulePath, size, win64.MEM_RELEASE)

			// Call remote LoadLibraryW with the remote module path.
			if hThread, err := win64.CreateRemoteThread(
				hProcess, nil, 0,
				procLoadLibraryW.Addr(), remoteModulePath,
				0, nil,
			); err != nil {
				return err
			} else {
				defer win64.CloseHandle(hThread)

				if code, err := win64.WaitForSingleObject(
					hThread, win64.DEFAULT_WAIT_MS,
				); err != nil {
					return err
				} else if code != win64.WAIT_OBJECT_0 {
					return errors.New("Failed to wait remote thread LoadLibraryW")
				}
			}
		}
	}

	return nil
}

func main() {
	// Set pid to inject.
	var pid uint32 = 15108
	dll, _ := filepath.Abs("../dll/a.dll")
	if err := InjectDLL(pid, dll); err != nil {
		fmt.Println("Failed to inject, err=", err.Error())
	} else {
		fmt.Println("Succeed to inject")
	}
}
