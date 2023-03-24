package win64

import (
	"syscall"
	"unsafe"
)

const (
	GW_HWNDFIRST    = 0
	GW_HWNDLAST     = 1
	GW_HWNDNEXT     = 2
	GW_HWNDPREV     = 3
	GW_OWNER        = 4
	GW_CHILD        = 5
	GW_ENABLEDPOPUP = 6
)

const (
	HWND_BOTTOM    = 1
	HWND_NOTOPMOST = -2
	HWND_TOP       = 0
	HWND_TOPMOST   = -1

	SWP_ASYNCWINDOWPOS = 0x4000
	SWP_DEFERERASE     = 0x2000
	SWP_DRAWFRAME      = 0x0020
	SWP_FRAMECHANGED   = 0x0020
	SWP_HIDEWINDOW     = 0x0080
	SWP_NOACTIVATE     = 0x0010
	SWP_NOCOPYBITS     = 0x0100
	SWP_NOMOVE         = 0x0002
	SWP_NOOWNERZORDER  = 0x0200
	SWP_NOREDRAW       = 0x0008
	SWP_NOREPOSITION   = 0x0200
	SWP_NOSENDCHANGING = 0x0400
	SWP_NOSIZE         = 0x0001
	SWP_NOZORDER       = 0x0004
	SWP_SHOWWINDOW     = 0x0040
)

const (
	SW_HIDE            = 0
	SW_SHOWNORMAL      = 1
	SW_NORMAL          = 1
	SW_SHOWMINIMIZED   = 2
	SW_SHOWMAXIMIZED   = 3
	SW_MAXIMIZE        = 3
	SW_SHOWNOACTIVATE  = 4
	SW_SHOW            = 5
	SW_MINIMIZE        = 6
	SW_SHOWMINNOACTIVE = 7
	SW_SHOWNA          = 8
	SW_RESTORE         = 9
	SW_SHOWDEFAULT     = 10
	SW_FORCEMINIMIZE   = 11
)

var (
	procEnumWindows              *syscall.LazyProc
	procIsWindowVisible          *syscall.LazyProc
	procGetWindow                *syscall.LazyProc
	procGetWindowThreadProcessId *syscall.LazyProc
	procSetForegroundWindow      *syscall.LazyProc
	procSetWindowPos             *syscall.LazyProc
	procShowWindow               *syscall.LazyProc
)

type EnumWindowsProc = func(hWnd syscall.Handle, param uintptr) uintptr

func EnumWindows(enumFunc EnumWindowsProc, param uintptr) (bool, error) {
	r1, _, e1 := syscall.SyscallN(procEnumWindows.Addr(),
		syscall.NewCallback(enumFunc), param)
	b := r1 != 0
	if !b {
		if e1 != ERROR_SUCCESS {
			return b, e1
		} else {
			return b, syscall.EINVAL
		}
	}
	return b, nil
}

func IsWindowVisible(hWnd syscall.Handle) (bool, error) {
	r1, _, e1 := syscall.SyscallN(procIsWindowVisible.Addr(), uintptr(hWnd))
	b := r1 != 0
	if !b {
		if e1 != ERROR_SUCCESS {
			return b, e1
		} else {
			return b, syscall.EINVAL
		}
	}
	return b, nil
}

func GetWindow(hWnd syscall.Handle, cmd uint) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procGetWindow.Addr(),
		uintptr(hWnd), uintptr(cmd))
	handle := syscall.Handle(r1)
	if handle == INVALID_HANDLE_VALUE {
		if e1 != ERROR_SUCCESS {
			return handle, e1
		} else {
			return handle, syscall.EINVAL
		}
	}
	return handle, nil
}

func GetWindowThreadProcessId(hWnd syscall.Handle, processID *uint32) (uint32, error) {
	r1, _, e1 := syscall.SyscallN(procGetWindowThreadProcessId.Addr(),
		uintptr(hWnd),
		uintptr(unsafe.Pointer(processID)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return 0, e1
		} else {
			return 0, syscall.EINVAL
		}
	}
	return uint32(r1), nil
}

func SetForegroundWindow(hWnd syscall.Handle) (bool, error) {
	r1, _, e1 := syscall.SyscallN(procSetForegroundWindow.Addr(), uintptr(hWnd))
	b := r1 != 0
	if !b {
		if e1 != ERROR_SUCCESS {
			return b, e1
		} else {
			return b, syscall.EINVAL
		}
	}
	return b, nil
}

func SetWindowPos(
	hWnd syscall.Handle,
	hWndInsertAfter syscall.Handle,
	X, Y, cx, cy int,
	flags uint,
) (bool, error) {
	r1, _, e1 := syscall.SyscallN(procSetWindowPos.Addr(),
		uintptr(hWnd),
		uintptr(hWndInsertAfter),
		uintptr(X), uintptr(Y), uintptr(cx), uintptr(cy),
		uintptr(flags))
	b := r1 != 0
	if !b {
		if e1 != ERROR_SUCCESS {
			return b, e1
		} else {
			return b, syscall.EINVAL
		}
	}
	return b, nil
}

func ShowWindow(hWnd syscall.Handle, nCmdShow int) (bool, error) {
	r1, _, e1 := syscall.SyscallN(procShowWindow.Addr(),
		uintptr(hWnd),
		uintptr(nCmdShow))
	b := r1 != 0
	if !b {
		if e1 != ERROR_SUCCESS {
			return b, e1
		} else {
			return b, syscall.EINVAL
		}
	}
	return b, nil
}
