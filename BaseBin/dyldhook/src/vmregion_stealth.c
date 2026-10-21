#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"
#include "dyld.h"

// External mach_task_self_ from main.c
extern mach_port_t mach_task_self_;

// Target address range where vm_region_64 fails (above 0x7000000000)
#define STEALTH_VM_BASE_ADDR    0x7000000000ULL
#define STEALTH_VM_MAX_SIZE     0x100000000ULL  // 4GB space

// Structure to track remapped libraries
typedef struct {
    vm_address_t original_addr;
    vm_address_t stealth_addr;
    vm_size_t size;
    bool is_remapped;
} stealth_mapping_t;

static stealth_mapping_t g_stealth_mappings[16];
static uint32_t g_stealth_mapping_count = 0;
static vm_address_t g_next_stealth_addr = STEALTH_VM_BASE_ADDR;

// Check if a path is a jailbreak library that needs hiding
static bool should_hide_dylib(const char *path)
{
    if (!path) return false;

    return (strstr(path, "systemhook.dylib") != NULL ||
            strstr(path, "libjailbreak.dylib") != NULL ||
            strstr(path, "libchoma.dylib") != NULL ||
            strstr(path, "libellekit.dylib") != NULL);
}

// Remap existing library to stealth region
static kern_return_t remap_to_stealth_region(vm_address_t original_addr, vm_size_t size, vm_prot_t prot)
{
    kern_return_t kr;
    vm_address_t stealth_addr = g_next_stealth_addr;

    // Allocate in stealth region
    kr = vm_allocate(mach_task_self_, &stealth_addr, size, VM_FLAGS_FIXED);
    if (kr != KERN_SUCCESS) {
        stealth_addr = 0;
        kr = vm_allocate(mach_task_self_, &stealth_addr, size,
                        VM_FLAGS_ANYWHERE | VM_MAKE_TAG(VM_MEMORY_DYLD));
        if (kr != KERN_SUCCESS) return kr;

        // If we couldn't get exact address, try to get one in high range
        if (stealth_addr < STEALTH_VM_BASE_ADDR) {
            vm_deallocate(mach_task_self_, stealth_addr, size);
            return KERN_NO_SPACE;
        }
    }

    // Copy original memory to stealth region
    kr = vm_copy(mach_task_self_, original_addr, size, stealth_addr);
    if (kr != KERN_SUCCESS) {
        // Fallback: manual copy
        memcpy((void *)stealth_addr, (void *)original_addr, size);
    }

    // Set proper protection
    kr = vm_protect(mach_task_self_, stealth_addr, size, FALSE, prot);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self_, stealth_addr, size);
        return kr;
    }

    // Deallocate original region
    vm_deallocate(mach_task_self_, original_addr, size);

    // Record mapping
    if (g_stealth_mapping_count < sizeof(g_stealth_mappings)/sizeof(g_stealth_mappings[0])) {
        g_stealth_mappings[g_stealth_mapping_count].original_addr = original_addr;
        g_stealth_mappings[g_stealth_mapping_count].stealth_addr = stealth_addr;
        g_stealth_mappings[g_stealth_mapping_count].size = size;
        g_stealth_mappings[g_stealth_mapping_count].is_remapped = true;
        g_stealth_mapping_count++;
    }

    g_next_stealth_addr = stealth_addr + size;
    g_next_stealth_addr = (g_next_stealth_addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1); // Page align

    return KERN_SUCCESS;
}

// Hook dyld's image loading to detect when jailbreak dylibs are mapped
extern void ORIG(_ZN5dyld44APIs13addDyldImageEPKN5dyld38MachOAnalyzerEPKNS0_11mach_headerEPKcb)(
    uintptr_t self, void *ma, void *mh, const char *path, bool prebound);

void HOOK(_ZN5dyld44APIs13addDyldImageEPKN5dyld38MachOAnalyzerEPKNS0_11mach_headerEPKcb)(
    uintptr_t self, void *ma, void *mh, const char *path, bool prebound)
{
    // Call original first
    ORIG(_ZN5dyld44APIs13addDyldImageEPKN5dyld38MachOAnalyzerEPKNS0_11mach_headerEPKcb)(self, ma, mh, path, prebound);

    // Only apply stealth remapping if jailbreak hiding is enabled
    if (!jbinfo_is_checked_in() || !jbinfo_is_hide_enabled()) {
        return;
    }

    if (should_hide_dylib(path)) {
        // Find all VM regions for this library
        vm_address_t address = (vm_address_t)mh;
        vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name;

        kern_return_t kr = vm_region_64(mach_task_self_, &address, &size,
                                        VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &count, &object_name);

        if (kr == KERN_SUCCESS) {
            // Remap this region to stealth area
            remap_to_stealth_region(address, size, info.protection);
        }
    }
}

// Hook mmap to redirect jailbreak dylibs to stealth region during initial load
extern void *ORIG(mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void *HOOK(mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    // Check if this is loading a jailbreak dylib by examining fd
    char path[PATH_MAX];
    if (fd >= 0 && fcntl(fd, F_GETPATH, path) == 0) {
        if (jbinfo_is_checked_in() && jbinfo_is_hide_enabled() && should_hide_dylib(path)) {
            // Force allocation in stealth region
            vm_address_t stealth_addr = g_next_stealth_addr;
            void *result = (void *)stealth_addr;

            kern_return_t kr = vm_allocate(mach_task_self_, &stealth_addr, len, VM_FLAGS_FIXED);
            if (kr == KERN_SUCCESS) {
                // Read file content directly into stealth memory
                lseek(fd, offset, SEEK_SET);
                read(fd, (void *)stealth_addr, len);
                vm_protect(mach_task_self_, stealth_addr, len, FALSE, prot);

                g_next_stealth_addr = stealth_addr + len;
                g_next_stealth_addr = (g_next_stealth_addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

                return (void *)stealth_addr;
            }
        }
    }

    return ORIG(mmap)(addr, len, prot, flags, fd, offset);
}
