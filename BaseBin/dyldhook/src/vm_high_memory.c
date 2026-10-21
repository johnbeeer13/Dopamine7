#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdint.h>
#include <stdbool.h>

// External functions
extern bool jbinfo_is_checked_in(void);
extern bool gDyldHookLog;
extern int _simple_dprintf(int fd, const char *format, ...);
extern bool gLoadingSystemhook;

// Declare the original vm_allocate trampoline from main.S (renamed from vm_allocate to _orig_vm_allocate)
extern kern_return_t _orig_vm_allocate(vm_map_t target, vm_address_t *address, vm_size_t size, int flags);

// iOS SDK type definitions for mach_vm functions
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t mach_vm_offset_t;
typedef uint64_t memory_object_offset_t;

// mach_vm_map - Mach trap #4816 on arm64
// We implement this via inline assembly to avoid external symbol dependency
static inline kern_return_t my_mach_vm_map(
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
)
{
    kern_return_t ret;
    register mach_vm_address_t *x1 __asm__("x1") = address;
    register mach_vm_size_t x2 __asm__("x2") = size;
    register mach_vm_offset_t x3 __asm__("x3") = mask;
    register int x4 __asm__("x4") = flags;
    register mach_port_t x5 __asm__("x5") = object;
    register memory_object_offset_t x6 __asm__("x6") = offset;
    register boolean_t x7 __asm__("x7") = copy;
    
    // Stack parameters
    register vm_prot_t x8 __asm__("x8") = cur_protection;
    register vm_prot_t x9 __asm__("x9") = max_protection;
    register vm_inherit_t x10 __asm__("x10") = inheritance;
    
    __asm__ volatile(
        "mov x0, %[task]\n"
        "mov x16, #0xffffffffffffffd0\n"  // -48 = mach_vm_map trap number
        "svc #0x80\n"
        "mov %[ret], x0\n"
        : [ret] "=r"(ret)
        : [task] "r"((mach_port_t)target_task), "r"(x1), "r"(x2), "r"(x3), 
          "r"(x4), "r"(x5), "r"(x6), "r"(x7), "r"(x8), "r"(x9), "r"(x10)
        : "x0", "x16", "memory"
    );
    
    return ret;
}

// Inline halt function to replace abort() - no external dependencies
static inline void halt_process(void)
{
    // Infinite loop - process will hang instead of calling abort()
    while (1) {
        __asm__ volatile("wfe");  // Wait for event - low power infinite loop
    }
}

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
            
            kr = my_mach_vm_map(
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
        halt_process();  // HARD STOP - NO FALLBACK
    }
    
    // Normal allocation for non-systemhook dylibs - use original trampoline
    return _orig_vm_allocate(target_task, address, size, flags);
}
