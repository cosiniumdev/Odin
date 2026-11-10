#+build linux
#+private
package mem_virtual

import "core:sys/linux"

// ThreadSanitizer cannot see raw syscalls. Its libc interceptors for `mmap` and `munmap` reset the shadow memory
// of a range, so a later mapping at a recycled address is not reported as a race with the earlier one.
@(private="file")
TSAN_ENABLED :: .Thread in ODIN_SANITIZER_FLAGS

when TSAN_ENABLED {
	foreign import libc "system:c"

	@(default_calling_convention="c", private="file")
	foreign libc {
		@(link_name="mmap")   _libc_mmap   :: proc(addr: rawptr, length: uint, prot, flags, fd: i32, offset: i64) -> rawptr ---
		@(link_name="munmap") _libc_munmap :: proc(addr: rawptr, length: uint) -> i32 ---
		@(link_name="__errno_location") _libc_errno_location :: proc() -> ^i32 ---
	}
}

@(private="file")
_mmap :: proc "contextless" (addr: uintptr, size: uint, prot: linux.Mem_Protection, flags: linux.Map_Flags, fd := linux.Fd(-1)) -> (rawptr, linux.Errno) {
	when TSAN_ENABLED {
		MAP_FAILED :: rawptr(~uintptr(0))
		ret := _libc_mmap(rawptr(addr), size, transmute(i32)prot, transmute(i32)flags, i32(fd), 0)
		if ret == MAP_FAILED {
			return nil, linux.Errno(_libc_errno_location()^)
		}
		return ret, .NONE
	} else {
		return linux.mmap(addr, size, prot, flags, fd, offset=0)
	}
}

_reserve :: proc "contextless" (size: uint, address_hint: uintptr) -> (data: []byte, err: Allocator_Error) {
	addr, errno := _mmap(address_hint, size, {}, {.PRIVATE, .ANONYMOUS})
	if errno == .ENOMEM {
		return nil, .Out_Of_Memory
	} else if errno == .EINVAL {
		return nil, .Invalid_Argument
	}
	return (cast([^]byte)addr)[:size], nil
}

_commit :: proc "contextless" (data: rawptr, size: uint) -> Allocator_Error {
	errno := linux.mprotect(data, size, {.READ, .WRITE})
	if errno == .EINVAL {
		return .Invalid_Pointer
	} else if errno == .ENOMEM {
		return .Out_Of_Memory
	}
	return nil
}

_decommit :: proc "contextless" (data: rawptr, size: uint) {
	_ = linux.mprotect(data, size, {})
	_ = linux.madvise(data, size, .FREE)
}

_release :: proc "contextless" (data: rawptr, size: uint) {
	when TSAN_ENABLED {
		_ = _libc_munmap(data, size)
	} else {
		_ = linux.munmap(data, size)
	}
}

_protect :: proc "contextless" (data: rawptr, size: uint, flags: Protect_Flags) -> bool {
	pflags: linux.Mem_Protection
	pflags = {}
	if .Read    in flags { pflags += {.READ}  }
	if .Write   in flags { pflags += {.WRITE} }
	if .Execute in flags { pflags += {.EXEC}  }
	errno := linux.mprotect(data, size, pflags)
	return errno == .NONE
}

_map_file :: proc "contextless" (fd: uintptr, size: i64, flags: Map_File_Flags) -> (data: []byte, error: Map_File_Error) {
	prot: linux.Mem_Protection
	if .Read in flags {
		prot += {.READ}
	}
	if .Write in flags {
		prot += {.WRITE}
	}

	flags := linux.Map_Flags{.SHARED}
	addr, errno := _mmap(0, uint(size), prot, flags, linux.Fd(fd))
	if addr == nil || errno != nil {
		return nil, .Map_Failure
	}
	return ([^]byte)(addr)[:size], nil
}

_unmap_file :: proc "contextless" (data: []byte) {
	_release(raw_data(data), uint(len(data)))
}
