#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <os/log.h>

// External functions
extern bool jbinfo_is_checked_in(void);
extern bool gDyldHookLog;
extern int _simple_dprintf(int fd, const char *format, ...);
extern bool gLoadingSystemhook;

// Global log file descriptor (opened once, reused)
static int g_logfd = -1;

// Forward declare syscall wrappers to avoid external dependencies
static inline int my_open(const char *path, int flags, int mode);
static inline ssize_t my_write(int fd, const void *buf, size_t count);
static inline int my_fsync(int fd);

// Syscall wrappers - no external dependencies
static inline int my_open(const char *path, int flags, int mode) {
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

static inline ssize_t my_write(int fd, const void *buf, size_t count) {
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

static inline int my_fsync(int fd) {
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

// Inline strlen to avoid external dependency
static inline size_t my_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

// Simple hex formatter for uint64_t
static inline void format_hex(char *buf, unsigned long long val) {
    const char hex[] = "0123456789abcdef";
    int i = 15;  // 16 hex digits for 64-bit
    buf[16] = '\0';
    while (i >= 0) {
        buf[i--] = hex[val & 0xF];
        val >>= 4;
    }
}

// Simple decimal formatter for int
static inline void format_dec(char *buf, int val) {
    if (val < 0) {
        *buf++ = '-';
        val = -val;
    }
    
    char tmp[16];
    int i = 0;
    do {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);
    
    while (i > 0) {
        *buf++ = tmp[--i];
    }
    *buf = '\0';
}

// Simple string copy
static inline void my_strcpy(char *dst, const char *src) {
    while (*src) {
        *dst++ = *src++;
    }
    *dst = '\0';
}

// Build log message with formatting
static inline void build_log_message(char *buf, const char *prefix, unsigned long long hex_val, const char *suffix) {
    my_strcpy(buf, prefix);
    char *p = buf + my_strlen(buf);
    
    if (hex_val != 0xFFFFFFFFFFFFFFFFULL) {  // Special marker for "no hex value"
        my_strcpy(p, "0x");
        p += 2;
        format_hex(p, hex_val);
        p += 16;
    }
    
    my_strcpy(p, suffix);
}

// Dual logging: stderr + file (/var/69/dyldhook_systemhook_loading.log) + console
static inline void log_message(const char *msg) {
    // 1. Log to stderr (fd 2) for compatibility
    my_write(2, msg, my_strlen(msg));
    my_write(2, "\n", 1);
    
    // 2. Log to console (os_log)
    os_log(OS_LOG_DEFAULT, "[dyldhook_mmap] %{public}s", msg);
    
    // 3. Log to file (/var/69/dyldhook_systemhook_loading.log)
    if (g_logfd < 0) {
        // Open log file (create if doesn't exist, append mode)
        // O_WRONLY=0x0001, O_CREAT=0x0200, O_APPEND=0x0008
        g_logfd = my_open("/var/69/dyldhook_systemhook_loading.log", 0x0001 | 0x0200 | 0x0008, 0644);
    }
    
    if (g_logfd >= 0) {
        my_write(g_logfd, msg, my_strlen(msg));
        my_write(g_logfd, "\n", 1);
        my_fsync(g_logfd);  // Force write to disk immediately
    }
}

// Declare the original mmap trampoline from main.S
extern void *_orig_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

// Simple string search for systemhook detection
static inline bool contains_systemhook(const char *str) {
    if (!str) return false;
    const char *needle = "systemhook";
    const char *haystack = str;
    
    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        
        while (*n && *h && (*h == *n)) {
            h++;
            n++;
        }
        
        if (*n == '\0') return true;
        haystack++;
    }
    return false;
}

// Get the current dylib being loaded from dyld's internal state
// This is a heuristic - check backtrace or dyld globals if available
static inline bool is_loading_systemhook(void) {
    // When gLoadingSystemhook is set, we know systemhook is being loaded
    return gLoadingSystemhook;
}

// NOTE: Function above is kept for compatibility but not used.
// The mmap hook now ONLY checks gLoadingSystemhook directly.

// Target high memory range: 0x7000000000 - 0x7FFFFFFFFFFF
#define HIGH_MEMORY_START  0x7000000000ULL
#define HIGH_MEMORY_END    0x7FFFFFFFFFULL
#define ALLOCATION_STEP    0x100000000ULL  // 4GB steps

// Override mmap - dyld will call THIS instead of the original
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    // Only intercept when systemhook is being loaded
    // Detect dylib segment mapping: MAP_PRIVATE + MAP_ANONYMOUS (or file-backed with fd >= 0)
    if (gLoadingSystemhook) {
        char logbuf[256];
        
        // Log the mmap() call parameters
        build_log_message(logbuf, "[dyldhook_mmap] *** INTERCEPTED (gLoadingSystemhook=TRUE) *** addr=", (unsigned long long)addr, ", length=");
        log_message(logbuf);
        
        build_log_message(logbuf, "[dyldhook_mmap]   flags=", (unsigned long long)flags, ", fd=");
        log_message(logbuf);
        
        format_dec(logbuf, fd);
        my_strcpy(logbuf + my_strlen(logbuf), ", prot=");
        format_dec(logbuf + my_strlen(logbuf), prot);
        log_message(logbuf);
        
        // Check if this is dyld mapping a segment (usually MAP_PRIVATE, and either MAP_ANONYMOUS or file-backed)
        // dyld typically uses: mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        // or: mmap(NULL, size, prot, MAP_PRIVATE, fd, offset) for file-backed segments
        bool is_dylib_mapping = (flags & MAP_PRIVATE) && (addr == NULL || addr == 0);
        
        if (is_dylib_mapping) {
            build_log_message(logbuf, "[dyldhook_mmap] *** DYLIB SEGMENT DETECTED *** FORCING HIGH MEMORY: length=", (unsigned long long)length, "");
            log_message(logbuf);

            // NO FALLBACK - Loop through high memory range with MAP_FIXED
            uint64_t try_addr = HIGH_MEMORY_START;
            void *result = MAP_FAILED;
            
            while (try_addr + length <= HIGH_MEMORY_END) {
                // Try to allocate at this specific address using MAP_FIXED
                result = _orig_mmap(
                    (void *)try_addr,
                    length,
                    prot,
                    (flags | MAP_FIXED),  // FORCE THIS EXACT ADDRESS
                    fd,
                    offset
                );
                
                if (result != MAP_FAILED && result == (void *)try_addr) {
                    build_log_message(logbuf, "[dyldhook_mmap] *** HIGH MEMORY SUCCESS at ", (unsigned long long)try_addr, " ***");
                    log_message(logbuf);
                    
                    return result;
                }
                
                // If failed and errno indicates address in use, try next address
                // Try next address (4GB step)
                try_addr += ALLOCATION_STEP;
            }
            
            // PANIC - Cannot allocate in high memory range
            build_log_message(logbuf, "[dyldhook_mmap] ***FATAL*** Cannot mmap() systemhook in high memory range ", HIGH_MEMORY_START, "-");
            log_message(logbuf);
            
            char hexbuf[32];
            format_hex(hexbuf, HIGH_MEMORY_END);
            my_strcpy(logbuf, "[dyldhook_mmap] ***FATAL*** Range end: 0x");
            my_strcpy(logbuf + my_strlen(logbuf), hexbuf);
            log_message(logbuf);
            
            build_log_message(logbuf, "[dyldhook_mmap] Last attempted address: ", try_addr - ALLOCATION_STEP, "");
            log_message(logbuf);
            
            // Return MAP_FAILED to signal error to dyld
            return MAP_FAILED;
        } else {
            build_log_message(logbuf, "[dyldhook_mmap] Non-dylib mapping (gLoadingSystemhook=TRUE but not dylib segment), passing through to _orig_mmap", 0xFFFFFFFFFFFFFFFFULL, "");
            log_message(logbuf);
        }
    }
    
    // Normal allocation for non-systemhook dylibs or non-dylib mappings - use original trampoline
    return _orig_mmap(addr, length, prot, flags, fd, offset);
}
