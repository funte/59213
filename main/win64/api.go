package win64

import (
	"syscall"
	"unsafe"
)

const (
	GENERIC_READ    = 0x80000000
	GENERIC_WRITE   = 0x40000000
	GENERIC_EXECUTE = 0x20000000
	GENERIC_ALL     = 0x10000000

	CREATE_NEW        = 1
	CREATE_ALWAYS     = 2
	OPEN_EXISTING     = 3
	OPEN_ALWAYS       = 4
	TRUNCATE_EXISTING = 5

	FILE_ATTRIBUTE_NORMAL = 0x00000080

	IMAGE_DOS_SIGNATURE              = 0x5A4D // MZ
	IMAGE_NT_SIGNATURE               = 0x4550 // PE00
	IMAGE_DIRECTORY_ENTRY_EXPORT     = 0      // Export Directory
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

	MAX_PATH          = 260
	MAX_MODULE_NAME32 = 255

	PROCESS_ALL_ACCESS = 0x001FFFFF

	PAGE_READWRITE = 0x04
	MEM_COMMIT     = 0x00001000
	MEM_RELEASE    = 0x00008000

	TH32CS_SNAPHEAPLIST = 0x00000001
	TH32CS_SNAPPROCESS  = 0x00000002
	TH32CS_SNAPTHREAD   = 0x00000004
	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x00000010
	TH32CS_SNAPALL      = TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE
	TH32CS_INHERIT      = 0x80000000

	INFINITE          = 0xFFFFFFFF
	DEFAULT_WAIT_MS   = 0x00002710 // 10秒
	LONG_WAIT_MS      = 0x00007530 // 30秒
	VERY_LONG_WAIT_MS = 0x0000EA60 // 60秒

	WAIT_FAILED        = 0xFFFFFFFF
	WAIT_OBJECT_0      = 0x00000000
	WAIT_ABANDONED     = 0x00000080
	WAIT_ABANDONED_0   = 0x00000080
	WAIT_IO_COMPLETION = 0x000000C0
)

// MessageBox flags.
// 更多信息参考: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
const (
	MB_OK                = 0x00000000
	MB_OKCANCEL          = 0x00000001
	MB_ABORTRETRYIGNORE  = 0x00000002
	MB_YESNOCANCEL       = 0x00000003
	MB_YESNO             = 0x00000004
	MB_RETRYCANCEL       = 0x00000005
	MB_CANCELTRYCONTINUE = 0x00000006

	MB_ICONHAND        = 0x00000010
	MB_ICONQUESTION    = 0x00000020
	MB_ICONEXCLAMATION = 0x00000030
	MB_ICONASTERISK    = 0x00000040

	MB_USERICON    = 0x00000080
	MB_ICONWARNING = MB_ICONEXCLAMATION
	MB_ICONERROR   = MB_ICONHAND

	MB_ICONINFORMATION = MB_ICONASTERISK
	MB_ICONSTOP        = MB_ICONHAND

	MB_DEFBUTTON1 = 0x00000000
	MB_DEFBUTTON2 = 0x00000100
	MB_DEFBUTTON3 = 0x00000200
	MB_DEFBUTTON4 = 0x00000300

	MB_APPLMODAL   = 0x00000000
	MB_SYSTEMMODAL = 0x00001000
	MB_TASKMODAL   = 0x00002000
	MB_HELP        = 0x00004000 // Help Button

	MB_NOFOCUS              = 0x00008000
	MB_SETFOREGROUND        = 0x00010000
	MB_DEFAULT_DESKTOP_ONLY = 0x00020000

	MB_TOPMOST    = 0x00040000
	MB_RIGHT      = 0x00080000
	MB_RTLREADING = 0x00100000

	MB_SERVICE_NOTIFICATION      = 0x00200000
	MB_SERVICE_NOTIFICATION_NT3X = 0x00040000

	MB_TYPEMASK = 0x0000000F
	MB_ICONMASK = 0x000000F0
	MB_DEFMASK  = 0x00000F00
	MB_MODEMASK = 0x00003000
	MB_MISCMASK = 0x0000C000
)

// Dialog Box Command IDs.
// 更多信息参考: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
const (
	IDOK     = 1
	IDCANCEL = 2
	IDABORT  = 3
	IDRETRY  = 4
	IDIGNORE = 5
	IDYES    = 6
	IDNO     = 7
	IDCLOSE  = 8
	IDHELP   = 9

	IDTRYAGAIN = 10
	IDCONTINUE = 11

	IDTIMEOUT = 32000
)

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DOS_HEADER struct {
	E_magic    uint16     // Magic number
	E_cblp     uint16     // Bytes on last page of file
	E_cp       uint16     // Pages in file
	E_crlc     uint16     // Relocations
	E_cparhdr  uint16     // Size of header in paragraphs
	E_minalloc uint16     // Minimum extra paragraphs needed
	E_maxalloc uint16     // Maximum extra paragraphs needed
	E_ss       uint16     // Initial (relative) SS value
	E_sp       uint16     // Initial SP value
	E_csum     uint16     // Checksum
	E_ip       uint16     // Initial IP value
	E_cs       uint16     // Initial (relative) CS value
	E_lfarlc   uint16     // File address of relocation table
	E_ovno     uint16     // Overlay number
	E_res      [4]uint16  // Reserved words
	E_oemid    uint16     // OEM identifier (for E_oeminfo)
	E_oeminfo  uint16     // OEM information; E_oemid specific
	E_res2     [10]uint16 // Reserved words
	E_lfanew   int32      // File address of new exe header
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint16
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type MODULEENTRY32W struct {
	Size           uint32
	ModuleID       uint32  // This module
	ProcessID      uint32  // owning process
	GlblcntUsage   uint32  // Global usage count on the module
	ProccntUsage   uint32  // Module usage count in th32ProcessID's context
	ModuleBaseAddr uintptr // Base address of module in th32ProcessID's context
	ModuleBaseSize uint32  // Size in bytes of module starting at modBaseAddr
	ModuleHandle   uintptr // The hModule of this module in th32ProcessID's context
	ModuleName     [MAX_MODULE_NAME32 + 1]uint16
	ExePath        [MAX_PATH]uint16
}

type PROCESSENTRY32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32 // this process
	DefaultHeapID   uintptr
	ModuleID        uint32 // associated exe
	Threads         uint32
	ParentProcessID uint32 // this process's parent process
	PriClassBase    int32  // Base priority of process's threads
	Flags           uint32 // Path
	ExeFile         [MAX_PATH]uint16
}

type SECURITY_ATTRIBUTES struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      int
}

var (
	INVALID_HANDLE_VALUE    = ^syscall.Handle(0)
	INVALID_FILE_SIZE       = 0xFFFFFFFF
	INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

	// Library
	libkernel32 *syscall.LazyDLL
	libuser32   *syscall.LazyDLL

	// Functions
	procCloseHandle                 *syscall.LazyProc
	procCreateFileA                 *syscall.LazyProc
	procCreateFileW                 *syscall.LazyProc
	procCreateRemoteThread          *syscall.LazyProc
	procCreateToolhelp32Snapshot    *syscall.LazyProc
	procFindClose                   *syscall.LazyProc
	procFindFirstFileA              *syscall.LazyProc
	procFindFirstFileW              *syscall.LazyProc
	procFindNextFileA               *syscall.LazyProc
	procFindNextFileW               *syscall.LazyProc
	procFreeLibrary                 *syscall.LazyProc
	procGetCurrentProcessId         *syscall.LazyProc
	procGetModuleHandleA            *syscall.LazyProc
	procGetModuleHandleW            *syscall.LazyProc
	procGetNamedPipeClientProcessId *syscall.LazyProc
	procGetProcAddress              *syscall.LazyProc
	procLoadLibraryA                *syscall.LazyProc
	procLoadLibraryW                *syscall.LazyProc
	procMessageBoxA                 *syscall.LazyProc
	procMessageBoxW                 *syscall.LazyProc
	procModule32FirstW              *syscall.LazyProc
	procModule32NextW               *syscall.LazyProc
	procOpenProcess                 *syscall.LazyProc
	procProcess32FirstW             *syscall.LazyProc
	procProcess32NextW              *syscall.LazyProc
	procReadFile                    *syscall.LazyProc
	procReadProcessMemory           *syscall.LazyProc
	procVirtualAllocEx              *syscall.LazyProc
	procVirtualFreeEx               *syscall.LazyProc
	procWaitForSingleObject         *syscall.LazyProc
	procWriteFile                   *syscall.LazyProc
	procWriteProcessMemory          *syscall.LazyProc
)

type FILETIME struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type WIN32_FIND_DATAA struct {
	FileAttributes    uint32
	CreationTime      FILETIME
	LastAccessTime    FILETIME
	LastWriteTime     FILETIME
	FileSizeHigh      uint32
	FileSizeLow       uint32
	Reserved0         uint32
	Reserved1         uint32
	FileName          [MAX_PATH]uint8
	AlternateFileName [14]uint8
}

type WIN32_FIND_DATAW struct {
	FileAttributes    uint32
	CreationTime      FILETIME
	LastAccessTime    FILETIME
	LastWriteTime     FILETIME
	FileSizeHigh      uint32
	FileSizeLow       uint32
	Reserved0         uint32
	Reserved1         uint32
	FileName          [MAX_PATH]uint16
	AlternateFileName [14]uint16
}

func boolToInterger(value bool) int {
	if value {
		return int(1)
	} else {
		return int(0)
	}
}

func CloseHandle(object syscall.Handle) error {
	r1, _, e1 := syscall.SyscallN(procCloseHandle.Addr(), uintptr(object))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func CreateFileA(
	filename *byte,
	desiredAccess uint32,
	shareMode uint32,
	securityAttributes uintptr,
	creationDisposition uint32,
	flagsAndAttributes uint32,
	hTemplateFile syscall.Handle,
) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procCreateFileA.Addr(),
		uintptr(unsafe.Pointer(filename)),
		uintptr(desiredAccess),
		uintptr(shareMode),
		securityAttributes,
		uintptr(creationDisposition),
		uintptr(flagsAndAttributes),
		uintptr(hTemplateFile))
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

func CreateFileW(
	filename *uint16,
	desiredAccess uint32,
	shareMode uint32,
	securityAttributes uintptr,
	creationDisposition uint32,
	flagsAndAttributes uint32,
	hTemplateFile syscall.Handle,
) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procCreateFileW.Addr(),
		uintptr(unsafe.Pointer(filename)),
		uintptr(desiredAccess),
		uintptr(shareMode),
		securityAttributes,
		uintptr(creationDisposition),
		uintptr(flagsAndAttributes),
		uintptr(hTemplateFile))
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

func CreateRemoteThread(
	hProcess syscall.Handle,
	threadAttributes *SECURITY_ATTRIBUTES,
	stackSize uint,
	startAddress uintptr,
	parameter uintptr,
	creationFlags uint32,
	threadID *uint32,
) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procCreateRemoteThread.Addr(),
		uintptr(hProcess),
		uintptr(unsafe.Pointer(threadAttributes)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(threadID)),
	)
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

func CreateToolhelp32Snapshot(flags, processID uint32) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procCreateToolhelp32Snapshot.Addr(),
		uintptr(flags),
		uintptr(processID))
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

func FindClose(findFile syscall.Handle) error {
	r1, _, e1 := syscall.SyscallN(procFindClose.Addr(), uintptr(findFile))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func FindFirstFileA(filename *uint8, findFileData *WIN32_FIND_DATAA) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procFindFirstFileA.Addr(),
		uintptr(unsafe.Pointer(filename)),
		uintptr(unsafe.Pointer(findFileData)))
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

func FindFirstFileW(filename *uint16, findFileData *WIN32_FIND_DATAW) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procFindFirstFileW.Addr(),
		uintptr(unsafe.Pointer(filename)),
		uintptr(unsafe.Pointer(findFileData)))
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

func FindNextFileA(hFindFile syscall.Handle, findFileData *WIN32_FIND_DATAA) error {
	r1, _, e1 := syscall.SyscallN(procFindNextFileA.Addr(),
		uintptr(hFindFile),
		uintptr(unsafe.Pointer(findFileData)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func FindNextFileW(hFindFile syscall.Handle, findFileData *WIN32_FIND_DATAW) error {
	r1, _, e1 := syscall.SyscallN(procFindNextFileW.Addr(),
		uintptr(hFindFile),
		uintptr(unsafe.Pointer(findFileData)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func FreeLibrary(hModule syscall.Handle) error {
	r1, _, e1 := syscall.SyscallN(procFreeLibrary.Addr(), uintptr(hModule))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func GetCurrentProcessId() uint32 {
	r1, _, _ := syscall.SyscallN(procGetCurrentProcessId.Addr())
	return uint32(r1)
}

func GetModuleHandleA(modulename *byte) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procGetModuleHandleA.Addr(),
		uintptr(unsafe.Pointer(modulename)))
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

func GetModuleHandleW(modulename *uint16) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procGetModuleHandleW.Addr(),
		uintptr(unsafe.Pointer(modulename)))
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

func GetNamedPipeClientProcessId(hPipe syscall.Handle, processID *uint32) error {
	r1, _, e1 := syscall.SyscallN(procGetNamedPipeClientProcessId.Addr(),
		uintptr(hPipe),
		uintptr(unsafe.Pointer(processID)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func GetProcAddress(hModule syscall.Handle, procname *byte) (uintptr, error) {
	r1, _, e1 := syscall.SyscallN(procGetProcAddress.Addr(),
		uintptr(hModule), uintptr(unsafe.Pointer(procname)))
	if r1 == 0 {
		if e1 != 0 {
			return 0, e1
		} else {
			return 0, syscall.EINVAL
		}
	}
	return r1, nil
}

func LoadLibraryA(filename *uint8) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procLoadLibraryA.Addr(), uintptr(unsafe.Pointer(filename)))
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

func LoadLibraryW(filename *uint16) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procLoadLibraryW.Addr(), uintptr(unsafe.Pointer(filename)))
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

func MessageBoxA(hWnd syscall.Handle, text, caption string, flags uint) (int, error) {
	r1, _, e1 := syscall.SyscallN(procMessageBoxA.Addr(),
		uintptr(hWnd),
		uintptr(unsafe.Pointer(syscall.StringBytePtr(text))),
		uintptr(unsafe.Pointer(syscall.StringBytePtr(caption))),
		uintptr(flags))
	code := int(r1)
	if code == 0 {
		if e1 != ERROR_SUCCESS {
			return code, e1
		} else {
			return code, syscall.EINVAL
		}
	}
	return code, nil
}

func MessageBoxAAsync(hWnd syscall.Handle, text, caption string, flags uint) {
	go func() {
		MessageBoxA(hWnd, text, caption, flags)
	}()
}

func MessageBoxW(hWnd syscall.Handle, text, caption string, flags uint) (int, error) {
	r1, _, e1 := syscall.SyscallN(procMessageBoxW.Addr(),
		uintptr(hWnd),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(caption))),
		uintptr(flags))
	code := int(r1)
	if code == 0 {
		if e1 != ERROR_SUCCESS {
			return code, e1
		} else {
			return code, syscall.EINVAL
		}
	}
	return code, nil
}

func MessageBoxWAsync(hWnd syscall.Handle, text, caption string, flags uint) {
	go func() {
		MessageBoxW(hWnd, text, caption, flags)
	}()
}

func Module32FirstW(hSnapshot syscall.Handle, me *MODULEENTRY32W) error {
	r1, _, e1 := syscall.SyscallN(procModule32FirstW.Addr(),
		uintptr(hSnapshot), uintptr(unsafe.Pointer(me)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func Module32NextW(hSnapshot syscall.Handle, me *MODULEENTRY32W) error {
	r1, _, e1 := syscall.SyscallN(procModule32NextW.Addr(),
		uintptr(hSnapshot), uintptr(unsafe.Pointer(me)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func OpenProcess(
	desiredAccess uint32,
	inheritHandle bool,
	processID uint32,
) (syscall.Handle, error) {
	r1, _, e1 := syscall.SyscallN(procOpenProcess.Addr(),
		uintptr(desiredAccess),
		uintptr(boolToInterger(inheritHandle)),
		uintptr(processID))
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

func Process32FirstW(hSnapshot syscall.Handle, pe *PROCESSENTRY32W) error {
	r1, _, e1 := syscall.Syscall(
		procProcess32FirstW.Addr(),
		2,
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(pe)),
		0)
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func Process32NextW(hSnapshot syscall.Handle, pe *PROCESSENTRY32W) error {
	r1, _, e1 := syscall.Syscall(
		procProcess32NextW.Addr(),
		2,
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(pe)),
		0)
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func ReadFile(
	hFile syscall.Handle,
	buffer *byte,
	numberOfBytesToRead uint32,
	numberOfBytesRead *uint32,
	overlapped uintptr,
) error {
	r1, _, e1 := syscall.SyscallN(procReadFile.Addr(),
		uintptr(hFile),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(numberOfBytesToRead),
		uintptr(unsafe.Pointer(numberOfBytesRead)),
		overlapped)
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func ReadProcessMemory(
	hProcess syscall.Handle,
	lpBaseAddress uintptr,
	lpBuffer uintptr,
	nSize uint,
	lpNumberOfBytesRead *uint,
) error {
	r1, _, e1 := syscall.SyscallN(procReadProcessMemory.Addr(),
		uintptr(hProcess),
		lpBaseAddress,
		lpBuffer,
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesRead)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func VirtualAllocEx(
	hProcess syscall.Handle,
	addr uintptr,
	size uint,
	allocationType uint32,
	protect uint32,
) (uintptr, error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAllocEx.Addr(),
		uintptr(hProcess),
		addr,
		uintptr(size),
		uintptr(allocationType),
		uintptr(protect))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return 0, e1
		} else {
			return 0, syscall.EINVAL
		}
	}
	return r1, nil
}

func VirtualFreeEx(hProcess syscall.Handle, addr uintptr, size uint, freeType uint32) error {
	r1, _, e1 := syscall.SyscallN(procVirtualFreeEx.Addr(),
		uintptr(hProcess),
		addr,
		uintptr(size),
		uintptr(freeType))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func WaitForSingleObject(handle syscall.Handle, milliseconds uint32) (uint32, error) {
	r1, _, e1 := syscall.SyscallN(procWaitForSingleObject.Addr(),
		uintptr(handle), uintptr(milliseconds))
	if r1 == WAIT_FAILED {
		if e1 != 0 {
			return uint32(r1), e1
		} else {
			return uint32(r1), syscall.EINVAL
		}
	}
	return uint32(r1), nil
}

func WriteFile(
	hFile syscall.Handle,
	buffer *byte,
	numberOfBytesToWrite uint32,
	numberOfBytesWritten *uint32,
	overlapped uintptr,
) error {
	r1, _, e1 := syscall.SyscallN(procWriteFile.Addr(),
		uintptr(hFile),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(numberOfBytesToWrite),
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
		overlapped)
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func WriteProcessMemory(
	hProcess syscall.Handle,
	baseAddress uintptr,
	buffer uintptr,
	size uint,
	numberOfBytesWritten *uint,
) error {
	r1, _, e1 := syscall.SyscallN(procWriteProcessMemory.Addr(),
		uintptr(hProcess),
		baseAddress,
		buffer,
		uintptr(size),
		uintptr(unsafe.Pointer(numberOfBytesWritten)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}
