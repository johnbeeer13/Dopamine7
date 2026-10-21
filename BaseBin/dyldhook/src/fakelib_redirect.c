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
#include <os/log.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"
#include "dyld.h"

// Dual logging helper - filesystem + console
static void dual_log_dlopen(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void dual_log_dlopen(const char *format, ...) {
	char buffer[1024];
	
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	
	// 1. Log to console (os_log)
	os_log(OS_LOG_DEFAULT, "[dyldhook_dlopen] %{public}s", buffer);
	
	// 2. Log to filesystem
	int fd = open("/var/69/dyldhook_systemhook_loading.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd >= 0) {
		write(fd, buffer, strlen(buffer));
		write(fd, "\n", 1);
		fsync(fd);
		close(fd);
	}
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
	dual_log_dlopen("=== dlopen_from() INTERCEPTED ===");
	dual_log_dlopen("  path: %s", path ? path : "(null)");
	dual_log_dlopen("  mode: 0x%x", mode);
	dual_log_dlopen("  addressInCaller: %p", addressInCaller);
	
	// Check if this is systemhook loading
	if (path && strstr(path, "systemhook")) {
		dual_log_dlopen("*** SYSTEMHOOK DETECTED in dlopen_from() ***");
		dual_log_dlopen("*** Full path: %s ***", path);
	}
	
	// Only redirect to .fakelib if hide jailbreak is actually enabled
	if (jbinfo_is_checked_in() && jbinfo_is_hide_enabled()) {
		dual_log_dlopen("  jbinfo: checked_in=TRUE, hide_enabled=TRUE");
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
					
					dual_log_dlopen("  REDIRECTING: %s -> %s", path, redirPath);

					void *handle = ORIG(_ZN5dyld44APIs11dlopen_fromEPKciPv)(self, redirPath, mode, addressInCaller);
					if (handle) {
						dual_log_dlopen("  REDIRECT SUCCESS: handle=%p", handle);
						return handle;
					} else {
						dual_log_dlopen("  REDIRECT FAILED, falling through to original path");
					}

					// If anything failed, fall through
				}
			}
		}
	} else {
		dual_log_dlopen("  jbinfo: checked_in=%d, hide_enabled=%d", 
			jbinfo_is_checked_in(), jbinfo_is_hide_enabled());
	}
	
	dual_log_dlopen("  Calling ORIG(dlopen_from) with path: %s", path);
	void *result = ORIG(_ZN5dyld44APIs11dlopen_fromEPKciPv)(self, path, mode, addressInCaller);
	dual_log_dlopen("  ORIG(dlopen_from) returned: %p", result);

	return result;
}

#endif