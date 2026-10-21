#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

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

// Get image size from mach header
static vm_size_t get_image_size(vm_address_t addr)
{
    const struct mach_header_64 *mh = (const struct mach_header_64 *)addr;
    if (!mh || mh->magic != MH_MAGIC_64) return 0;

    const struct load_command *lc = (const struct load_command *)(mh + 1);
    vm_size_t total_size = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            vm_address_t end = seg->vmaddr + seg->vmsize;
            if (end > total_size) {
                total_size = end;
            }
        }
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    return total_size;
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

// Callback for dyld image loading
static void vmregion_stealth_image_callback(const struct mach_header* mh, intptr_t vmaddr_slide) {
    // Only remap if hiding is enabled
    if (!jbinfo_is_hide_enabled()) {
        return;
    }
    
    // Get the image path from the mach header
    const char* path = NULL;
    Dl_info info;
    if (dladdr(mh, &info) && info.dli_fname) {
        path = info.dli_fname;
    }
    
    if (!path) return;

    // Check if this is a jailbreak dylib
    if (should_hide_dylib(path)) {
        // Get the loaded image's actual address and size
        vm_address_t original_addr = (vm_address_t)mh + vmaddr_slide;
        vm_size_t size = get_image_size(original_addr);
        
        if (size > 0) {
            vm_prot_t prot = VM_PROT_READ | VM_PROT_EXECUTE;
            remap_to_stealth_region(original_addr, size, prot);
        }
    }
}

// Constructor to register our callback
__attribute__((constructor))
static void vmregion_stealth_init(void) {
    _dyld_register_func_for_add_image(vmregion_stealth_image_callback);
}
