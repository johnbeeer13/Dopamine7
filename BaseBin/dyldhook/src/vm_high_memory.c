#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// External functions
extern bool jbinfo_is_checked_in(void);
extern bool gDyldHookLog;
extern int _simple_dprintf(int fd, const char *format, ...);
extern bool gLoadingSystemhook;

// Declare mach_vm_allocate for fallback (exists in iOS SDK)
extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

// iOS SDK type definitions for mach_vm functions
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t mach_vm_offset_t;
typedef uint64_t memory_object_offset_t;

// Declare mach_vm_map (iOS SDK doesn't expose it in headers but it exists in the kernel)
extern kern_return_t mach_vm_map(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    mach_port_t object,
    memory_object_offset_t offset,
    boolean_t copy,
    vm_prot_t cur_protection,
    vm_prot_t max_protection,
    vm_inherit_t inheritance
);

// Target high memory range: 0x7000000000 - 0x7FFFFFFFFFFF
#define HIGH_MEMORY_START  0x7000000000ULL
#define HIGH_MEMORY_END    0x7FFFFFFFFFULL
#define ALLOCATION_STEP    0x100000000ULL  // 4GB steps

// Override vm_allocate - dyld will call THIS instead of the original
kern_return_t vm_allocate(vm_map_t target_task, vm_address_t *address, vm_size_t size, int flags)
{
    // Only intercept for jailbroken processes with systemhook
    if (jbinfo_is_checked_in() && gLoadingSystemhook && (flags & VM_FLAGS_ANYWHERE)) {
        if (gDyldHookLog) {
            _simple_dprintf(2, "[dyldhook] FORCING HIGH MEMORY for systemhook: size=0x%llx\n", (unsigned long long)size);
        }

        // NO FALLBACK - Loop through high memory range with VM_FLAGS_FIXED
        mach_vm_address_t try_addr = HIGH_MEMORY_START;
        kern_return_t kr = KERN_FAILURE;
        
        while (try_addr + size <= HIGH_MEMORY_END) {
            mach_vm_address_t test_addr = try_addr;
            
            kr = mach_vm_map(
                target_task,
                &test_addr,
                (mach_vm_size_t)size,
                0,
                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,  // FORCE THIS EXACT ADDRESS
                MACH_PORT_NULL,
                0,
                FALSE,
                VM_PROT_DEFAULT,
                VM_PROT_ALL,
                VM_INHERIT_DEFAULT
            );
            
            if (kr == KERN_SUCCESS) {
                *address = (vm_address_t)test_addr;
                if (gDyldHookLog) {
                    _simple_dprintf(2, "[dyldhook] *** HIGH MEMORY SUCCESS at 0x%llx ***\n", (unsigned long long)test_addr);
                }
                return KERN_SUCCESS;
            }
            
            // Try next address
            try_addr += ALLOCATION_STEP;
        }
        
        // PANIC - Cannot allocate in high memory range
        _simple_dprintf(2, "[dyldhook] ***FATAL*** Cannot allocate systemhook in high memory range 0x%llx-0x%llx\n",
                       HIGH_MEMORY_START, HIGH_MEMORY_END);
        _simple_dprintf(2, "[dyldhook] Last error: kr=%d\n", kr);
        abort();  // HARD STOP - NO FALLBACK
    }
    
    // Normal allocation for non-systemhook dylibs
    mach_vm_address_t addr = (mach_vm_address_t)*address;
    kern_return_t kr = mach_vm_allocate(target_task, &addr, (mach_vm_size_t)size, flags);
    *address = (vm_address_t)addr;
    return kr;
}
