#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"
#include "dyld.h"

// Syscall wrappers for logging
static inline int my_open_dlopen(const char *path, int flags, int mode);
static inline ssize_t my_write_dlopen(int fd, const void *buf, size_t count);
static inline int my_fsync_dlopen(int fd);
static inline int my_close_dlopen(int fd);

static inline int my_open_dlopen(const char *path, int flags, int mode) {
    register long syscall_num __asm__("x16") = 5; // SYS_open
    register const char *x0 __asm__("x0") = path;
    register int x1 __asm__("x1") = flags;
    register int x2 __asm__("x2") = mode;
    register long result __asm__("x0");
    
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(result)
        : "r"(syscall_num), "r"(x0), "r"(x1), "r"(x2)
        : "memory"
    );
    
    return (int)result;
}

static inline ssize_t my_write_dlopen(int fd, const void *buf, size_t count) {
    register long syscall_num __asm__("x16") = 4; // SYS_write
    register int x0 __asm__("x0") = fd;
    register const void *x1 __asm__("x1") = buf;
    register size_t x2 __asm__("x2") = count;
    register long result __asm__("x0");
    
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(result)
        : "r"(syscall_num), "r"(x0), "r"(x1), "r"(x2)
        : "memory"
    );
    
    return (ssize_t)result;
}

static inline int my_fsync_dlopen(int fd) {
    register long syscall_num __asm__("x16") = 95; // SYS_fsync
    register int x0 __asm__("x0") = fd;
    register long result __asm__("x0");
    
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(result)
        : "r"(syscall_num), "r"(x0)
        : "memory"
    );
    
    return (int)result;
}

static inline int my_close_dlopen(int fd) {
    register long syscall_num __asm__("x16") = 6; // SYS_close
    register int x0 __asm__("x0") = fd;
    register long result __asm__("x0");
    
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(result)
        : "r"(syscall_num), "r"(x0)
        : "memory"
    );
    
    return (int)result;
}

// Simple string functions
static inline void my_strcpy_dlopen(char *dst, const char *src) {
    while (*src) {
        *dst++ = *src++;
    }
    *dst = '\0';
}

static inline size_t my_strlen_dlopen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

// Filesystem-only logging helper
static void fs_log_dlopen(const char *msg) {
    // O_WRONLY=0x0001, O_CREAT=0x0200, O_APPEND=0x0008
    int fd = my_open_dlopen("/var/69/dyldhook_systemhook_loading.log", 0x0001 | 0x0200 | 0x0008, 0644);
    if (fd >= 0) {
        my_write_dlopen(fd, msg, my_strlen_dlopen(msg));
        my_write_dlopen(fd, "\n", 1);
        my_fsync_dlopen(fd);
        my_close_dlopen(fd);
    }
    
    // Also log to stderr
    my_write_dlopen(2, msg, my_strlen_dlopen(msg));
    my_write_dlopen(2, "\n", 1);
}

// When hiding the jailbreak in Dopamine settings, a lot of processes will crash due to the /usr/lib mount disappearing
// Anything that has libraries inside /usr/lib that are not in the shared cache (e.g. libobjc_trampolines.dylib) mapped in will crash
// We solve this here by redirecting dlopen calls for files in /usr/lib to /var/69/basebin/.fakelib (if the latter is accessible)
// This way the vnode will not be on /usr/lib mount and the /usr/lib mount therefore can be unmounted without making stuff crash
// There are a few rare edge cases of processes that cannot access /var/69/basebin/.fakelib for some reason, so we need to make sure those still go over /usr/lib
// NOTE: This redirection ONLY happens when hide jailbreak is actually enabled!

#if IOS < 18

extern void *ORIG(_ZN5dyld44APIs11dlopen_fromEPKciPv)(uintptr_t self, const char* path, int mode, void* addressInCaller);
void *HOOK(_ZN5dyld44APIs11dlopen_fromEPKciPv)(uintptr_t self, const char* path, int mode, void* addressInCaller)
{
	// Log every dlopen_from call
	fs_log_dlopen("=== dlopen_from() INTERCEPTED ===");
	
	char logbuf[512];
	my_strcpy_dlopen(logbuf, "  path: ");
	if (path) {
		my_strcpy_dlopen(logbuf + my_strlen_dlopen(logbuf), path);
	} else {
		my_strcpy_dlopen(logbuf + my_strlen_dlopen(logbuf), "(null)");
	}
	fs_log_dlopen(logbuf);
	
	// Check if this is systemhook loading
	if (path && strstr(path, "systemhook")) {
		fs_log_dlopen("*** SYSTEMHOOK DETECTED in dlopen_from() ***");
		my_strcpy_dlopen(logbuf, "*** Full path: ");
		my_strcpy_dlopen(logbuf + my_strlen_dlopen(logbuf), path);
		my_strcpy_dlopen(logbuf + my_strlen_dlopen(logbuf), " ***");
		fs_log_dlopen(logbuf);
	}
	
	// Only redirect to .fakelib if hide jailbreak is actually enabled
	if (jbinfo_is_checked_in() && jbinfo_is_hide_enabled()) {
		fs_log_dlopen("  jbinfo: checked_in=TRUE, hide_enabled=TRUE");
		if (!access(path, F_OK)) {
			const char *orgPrefix = "/usr/lib/";
    		size_t orgPrefixLen = strlen(orgPrefix);
			if (!strncmp(path, orgPrefix, orgPrefixLen)) {
				char *jbroot = jbinfo_get_jbroot();
				if (jbroot) {
					const char *suffix = &path[orgPrefixLen-1];
					const char *middle = "/basebin/.fakelib";

					size_t redirPathSize = strlen(suffix) + strlen(middle) + strlen(jbroot) + 1;
					char redirPath[redirPathSize];
					strlcpy(redirPath, jbroot, redirPathSize);
					strlcat(redirPath, middle, redirPathSize);
					strlcat(redirPath, suffix, redirPathSize);
					
					my_strcpy_dlopen(logbuf, "  REDIRECTING to: ");
					my_strcpy_dlopen(logbuf + my_strlen_dlopen(logbuf), redirPath);
					fs_log_dlopen(logbuf);

					void *handle = ORIG(_ZN5dyld44APIs11dlopen_fromEPKciPv)(self, redirPath, mode, addressInCaller);
					if (handle) {
						fs_log_dlopen("  REDIRECT SUCCESS");
						return handle;
					} else {
						fs_log_dlopen("  REDIRECT FAILED, falling through to original path");
					}

					// If anything failed, fall through
				}
			}
		}
	} else {
		fs_log_dlopen("  jbinfo: checked_in or hide_enabled is FALSE");
	}
	
	fs_log_dlopen("  Calling ORIG(dlopen_from)");
	void *result = ORIG(_ZN5dyld44APIs11dlopen_fromEPKciPv)(self, path, mode, addressInCaller);
	if (result) {
		fs_log_dlopen("  ORIG(dlopen_from) SUCCESS");
	} else {
		fs_log_dlopen("  ORIG(dlopen_from) FAILED");
	}

	return result;
}

#endif