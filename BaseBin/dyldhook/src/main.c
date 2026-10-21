#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <libjailbreak/jbclient_mach.h>

#include "dyld.h"
#include "dyld_jbinfo.h"

// Syscall wrappers for logging
static inline int my_open_log(const char *path, int flags, int mode);
static inline ssize_t my_write_log(int fd, const void *buf, size_t count);
static inline int my_fsync_log(int fd);
static inline int my_close_log(int fd);

static inline int my_open_log(const char *path, int flags, int mode) {
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

static inline ssize_t my_write_log(int fd, const void *buf, size_t count) {
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

static inline int my_fsync_log(int fd) {
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

static inline int my_close_log(int fd) {
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

// dup() syscall wrapper
static inline int my_dup_log(int oldfd) {
    register long syscall_num __asm__("x16") = 41; // SYS_dup
    register int x0 __asm__("x0") = oldfd;
    register long result __asm__("x0");
    
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(result)
        : "r"(syscall_num), "r"(x0)
        : "memory"
    );
    
    return (int)result;
}

// Simple string copy
static inline void my_strcpy_log(char *dst, const char *src) {
    while (*src) {
        *dst++ = *src++;
    }
    *dst = '\0';
}

// Simple strlen
static inline size_t my_strlen_log(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

// Filesystem-only logging helper (no stderr to avoid EXC_GUARD, no os_log to avoid external symbols)
// CRITICAL: Avoid closing low fds (0,1,2) which may be guarded by the system
static void fs_log(const char *msg) {
    // O_WRONLY=0x0001, O_CREAT=0x0200, O_APPEND=0x0008
    int fd = my_open_log("/var/69/dyldhook_systemhook_loading.log", 0x0001 | 0x0200 | 0x0008, 0644);
    if (fd >= 0) {
        // CRITICAL FIX: If we got fd 0, 1, or 2 (stdin/stdout/stderr range),
        // dup() it to a higher number to avoid closing guarded system fds
        if (fd <= 2) {
            int new_fd = my_dup_log(fd);  // Get a higher fd number
            my_close_log(fd);  // Close the low number (this is safe - it's our newly opened file)
            fd = new_fd;  // Use the higher number from here on
        }
        
        if (fd >= 0) {
            my_write_log(fd, msg, my_strlen_log(msg));
            my_write_log(fd, "\n", 1);
            my_fsync_log(fd);
            my_close_log(fd);  // Now safe to close - it's fd >= 3
        }
    }
}

bool gDyldHookLog = false;
bool gLoadingSystemhook = false;

__attribute__((section("__DATA,__jbinfo"))) static char jbinfoSection[0x4000];
#define jbInfo ((struct dyld_jbinfo *)&jbinfoSection[0])

bool gDyldhookInitDone = false;

bool jbinfo_is_checked_in(void)
{
	return jbInfo->state == DYLD_STATE_CHECKED_IN;
}

char *jbinfo_get_jbroot(void)
{
	return jbInfo->jbRootPath;
}

bool jbinfo_should_force_cs_adhoc(void)
{
	return jbInfo->forceCSAdhoc;
}

bool jbinfo_is_hide_enabled(void)
{
	return jbInfo->hideEnabled;
}

void consume_tokenized_sandbox_extensions(char *sandboxExtensions)
{
	if (sandboxExtensions[0] == '\0') return;

	char *it = sandboxExtensions;
	char *last = sandboxExtensions;
	while (*(++it) != '\0') {
		if (*it == '|') {
			*it = '\0';
			sandbox_extension_consume(last);
			last = &it[1];
			*it = '|';
		}
	}
	sandbox_extension_consume(last);
}

void dyldhook_perform_checkin(void)
{
	struct jbserver_mach_msg_checkin_reply *replyPtr; // Only for sizeof macro

	char *jbRootPathPtr = &jbInfo->data[0];
	char *bootUUIDPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)];
	char *sandboxExtensionsPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)+sizeof(replyPtr->bootUUID)];

	// Tell jbserver (in launchd) that this process exists
	// This will, amongst other things, disable page validation, which allows instruction hooks to be applied later
	if (jbclient_mach_process_checkin(jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr, &jbInfo->fullyDebugged, &jbInfo->forceCSAdhoc, &jbInfo->hideEnabled) == 0) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Performed checkin [%s %s %s]\n", jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr);
		}
		consume_tokenized_sandbox_extensions(sandboxExtensionsPtr);
		jbInfo->jbRootPath = jbRootPathPtr;
		jbInfo->bootUUID = bootUUIDPtr;
		jbInfo->sandboxExtensions = sandboxExtensionsPtr;
		jbInfo->state = DYLD_STATE_CHECKED_IN;
	}
	else {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Checkin failed???\n");
		}
	}
}

int simple_atoi(char *p)
{
	int negate = p[0] == '-';
	if (negate) p++;

    int k = 0;
    while (*p) {
		if (*p >= '0' && *p <= '9') {
			k = k * 10 + (*p) - '0';
		}
		p++;
	}

	return (negate ? -1 : 1) * k;
}

mach_port_t mach_task_self_ = MACH_PORT_NULL;
void mach_init_4real(void)
{
	// Because mach_init has a "call once" mechanism, we can just call it ourselves without breaking anything in the later dyld flow
	// This allows us to have a proper pthread descriptor which fixes a whole bunch of stuff
	extern void mach_init(void);
	mach_init(); // This sets up mach_task_self_ in dyld but we can't get it since getting a global from dyld is not implemented in MachOMerger

	mach_task_self_ = task_self_trap();
	// Apparently task_self_trap increases the refcount of the task so we call deallocate again to decrease it
	mach_port_deallocate(mach_task_self_, mach_task_self_);
}

void dyldhook_init(uintptr_t kernelParams)
{
	fs_log("=== dyldhook_init() ENTRY ===");
	
	mach_init_4real();

	// If we are in launchd, bail out
	if (getpid() == 1) {
		fs_log("=== dyldhook_init() EXIT - launchd bail out ===");
		return;
	}

	// Walk kernelParams to get envp
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	char **argv = (char **)(kernelParams + sizeof(void *) + sizeof(argc));
	char **envp = (char **)(kernelParams + sizeof(void *) + sizeof(argc) + (sizeof(const char *) * argc) + sizeof(void *));
	
	fs_log("Parsed argc/argv/envp");

	if (_simple_getenv(envp, "DYLD_HOOK_PRINT") != NULL) {
		gDyldHookLog = true;
		fs_log("DYLD_HOOK_PRINT enabled");
	}

	if (_simple_getenv(envp, "DYLD_HOOK_SETUID") != NULL) {
		int uid = 0, gid = 0, ruid = 0, rgid = 0, fd = -1;
		gid_t groups[NGROUPS_MAX] = { 0 };

		for (int i = 1; i < argc; i++) {
			if (gDyldHookLog) {
				_simple_dprintf(2, "Processing %s\n", argv[i]);
			}

			int r = argc - i - 1;
			if (!strcmp(argv[i], "--fd")) {
				if (r < 1) break;
				fd = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--uid")) {
				if (r < 1) break;
				uid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--ruid")) {
				if (r < 1) break;
				ruid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--gid")) {
				if (r < 1) break;
				gid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--rgid")) {
				if (r < 1) break;
				rgid = simple_atoi(argv[++i]);
			}
			else if (!strcmp(argv[i], "--groups")) {
				if (r < NGROUPS_MAX) break;
				for (int k = 0; k < NGROUPS_MAX; k++) {
					groups[k] = simple_atoi(argv[++i]);
				}
			}
		}

		if (gDyldHookLog) {
			_simple_dprintf(2, "DYLD_HOOK_SETUID (fd=%d, uid=%d, ruid=%d, gid=%d, rgid=%d)\n", fd, uid, ruid, gid, rgid);
		}

		if (fd == -1) return;

		setgid(gid);
		setgid(gid);
		setregid(rgid, -1);
		int ngroups;
		for (ngroups = 0; ngroups < NGROUPS_MAX; ngroups++) {
			if (groups[ngroups] == -1) break;
		}
		setgroups(ngroups, groups);
		setuid(uid);
		setuid(uid);
		setreuid(ruid, -1);

		// if (gDyldHookLog) {
		// 	uid_t uid  = getuid();
		// 	uid_t euid = geteuid();
		// 	gid_t gid  = getgid();
		// 	gid_t egid = getegid();

		// 	_simple_dprintf(2, "PID  : %d\n", (int)getpid());
		// 	_simple_dprintf(2, "PPID : %d\n", (int)getppid());
		// 	_simple_dprintf(2, "uid  : real=%d  effective=%d\n", (int)uid,  (int)euid);
		// 	_simple_dprintf(2, "gid  : real=%d  effective=%d\n", (int)gid,  (int)egid);
		// }

		char r = 0x42;
		write(fd, &r, sizeof(r));

		__asm("b .");
	}

	// If DYLD_INSERT_LIBRARIES is not set or does not contain systemhook, bail out
	const char *insertLibrariesVar = _simple_getenv(envp, "DYLD_INSERT_LIBRARIES");
	
	char logbuf[512];
	my_strcpy_log(logbuf, "Checking DYLD_INSERT_LIBRARIES: ");
	if (insertLibrariesVar) {
		my_strcpy_log(logbuf + my_strlen_log(logbuf), insertLibrariesVar);
	} else {
		my_strcpy_log(logbuf + my_strlen_log(logbuf), "(null)");
	}
	fs_log(logbuf);
	
	if (!insertLibrariesVar) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Not checking in, DYLD_INSERT_LIBRARIES was not found\n");
		}
		fs_log("=== dyldhook_init() EXIT - No DYLD_INSERT_LIBRARIES ===");
		return;		
	}
	if (!strstr(insertLibrariesVar, "/systemhook.dylib")) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Not checking in, no systemhook found in DYLD_INSERT_LIBRARIES (%s)\n", insertLibrariesVar);
		}
		fs_log("=== dyldhook_init() EXIT - No systemhook in DYLD_INSERT_LIBRARIES ===");
		return;
	}
	
	fs_log("*** SYSTEMHOOK DETECTED in DYLD_INSERT_LIBRARIES ***");
	my_strcpy_log(logbuf, "*** Full path: ");
	my_strcpy_log(logbuf + my_strlen_log(logbuf), insertLibrariesVar);
	my_strcpy_log(logbuf + my_strlen_log(logbuf), " ***");
	fs_log(logbuf);

	// Enable high memory allocation for systemhook loading
	gLoadingSystemhook = true;
	fs_log("*** gLoadingSystemhook = TRUE - mmap hook ACTIVATED ***");
	
	if (gDyldHookLog) {
		_simple_dprintf(2, "Enabled high memory allocation for systemhook\n");
	}

	// If all is well, do check-in right here before dyld_start!
	fs_log("Calling dyldhook_perform_checkin()...");
	dyldhook_perform_checkin();
	fs_log("=== dyldhook_init() EXIT - checkin complete ===");
}