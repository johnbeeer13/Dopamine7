#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

// External functions
extern bool jbinfo_is_checked_in(void);
extern bool gDyldHookLog;
extern int _simple_dprintf(int fd, const char *format, ...);
extern bool gLoadingSystemhook;

// Import the original libsystem vm_allocate
extern kern_return_t __kernelrpc_vm_allocate(vm_map_t target, vm_offset_t *address, vm_size_t size, int flags);

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
    return __kernelrpc_vm_allocate(target_task, (vm_offset_t *)address, size, flags);
}
