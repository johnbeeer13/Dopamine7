#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>

// External functions
extern bool jbinfo_is_checked_in(void);
extern bool gDyldHookLog;
extern int _simple_dprintf(int fd, const char *format, ...);
extern bool gLoadingSystemhook;

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
        // Check if this is dyld mapping a segment (usually MAP_PRIVATE, and either MAP_ANONYMOUS or file-backed)
        // dyld typically uses: mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        // or: mmap(NULL, size, prot, MAP_PRIVATE, fd, offset) for file-backed segments
        bool is_dylib_mapping = (flags & MAP_PRIVATE) && (addr == NULL || addr == 0);
        
        if (is_dylib_mapping) {
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
                    return result;
                }
                
                // If failed and errno indicates address in use, try next address
                // Try next address (4GB step)
                try_addr += ALLOCATION_STEP;
            }
            
            // PANIC - Cannot allocate in high memory range
            // Return MAP_FAILED to signal error to dyld
            return MAP_FAILED;
        }
    }
    
    // Normal allocation for non-systemhook dylibs or non-dylib mappings - use original trampoline
    return _orig_mmap(addr, length, prot, flags, fd, offset);
}
