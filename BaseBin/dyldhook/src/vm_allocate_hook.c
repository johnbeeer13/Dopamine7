#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"

// Track if we're currently loading systemhook.dylib
// This will be set by dyldhook_init when systemhook is detected in DYLD_INSERT_LIBRARIES
bool gLoadingSystemhook = false;

// Hook mach_vm_allocate to force systemhook.dylib to load at 0x700000000000
extern kern_return_t ORIG(_kernelrpc_mach_vm_allocate_trap)(
	mach_port_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

kern_return_t HOOK(_kernelrpc_mach_vm_allocate_trap)(
	mach_port_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
)
{
	// Only modify allocation if:
	// 1. We're checked in with jbserver
	// 2. systemhook.dylib was detected in DYLD_INSERT_LIBRARIES
	// 3. This appears to be a dylib allocation (reasonable size)
	if (jbinfo_is_checked_in() && gLoadingSystemhook) {
		// Allocations for dylibs are typically in the MB range
		// Check if this looks like a dylib mapping request
		if (size > 0x1000 && size < 0x10000000) { // Between 4KB and 256MB
			// Force allocation at high address range: 0x700000000000 - 0x7FFFFFFFFFFF
			*address = 0x700000000000ULL;
			// Use VM_FLAGS_FIXED to force this exact address
			// VM_FLAGS_ANYWHERE = 0x0001, VM_FLAGS_FIXED = 0x0000
			flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
			
			// Attempt allocation at high address
			kern_return_t result = ORIG(_kernelrpc_mach_vm_allocate_trap)(target, address, size, flags);
			
			// If it worked, return success
			if (result == KERN_SUCCESS) {
				return result;
			}
			
			// If it failed, fall through to default behavior
			// Reset address and flags to allow dyld to pick a location
			*address = 0;
			flags = VM_FLAGS_ANYWHERE;
		}
	}
	
	// Call original mach_vm_allocate
	return ORIG(_kernelrpc_mach_vm_allocate_trap)(target, address, size, flags);
}

// Alternative approach: Hook at mach_vm_allocate level (higher-level wrapper)
// Keeping this for reference but using the trap version above for earlier interception

/*
extern kern_return_t ORIG(mach_vm_allocate)(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

kern_return_t HOOK(mach_vm_allocate)(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
)
{
	// Same logic as above but at higher level
	if (jbinfo_is_checked_in() && gLoadingSystemhook) {
		if (size > 0x1000 && size < 0x10000000) {
			*address = 0x700000000000ULL;
			flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
			
			kern_return_t result = ORIG(mach_vm_allocate)(target, address, size, flags);
			if (result == KERN_SUCCESS) {
				return result;
			}
			
			*address = 0;
			flags = VM_FLAGS_ANYWHERE;
		}
	}
	
	return ORIG(mach_vm_allocate)(target, address, size, flags);
}
*/
