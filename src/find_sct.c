#include "hook.h"
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/irq_vectors.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/proto.h>
#include <linux/delay.h>

#include <linux/kallsyms.h>

#define DEBUG_MODULE 	0

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif

/*
 *  To get the 32-bit syscall handler we consult the 0x80
 *  interrupt handler in the interrupt descriptor table. To get the 64-bit
 *  syscall handler we consult the LSTAR MSR.
 */

static inline void x86_put_jmp(void *hook_me_func, void *I_will_catch_you) {
	*((u8 *) (hook_me_func)) = 0xE9; /* JMP opcode -- E9.xx.xx.xx.xx */
	*((int *) (hook_me_func + 1)) = (long) (I_will_catch_you - (hook_me_func));
}

static inline void x86_remove_jmp(void *hook_me_func) {
	*((char *) (hook_me_func + 0)) = 0x90; /* JMP opcode -- E9.xx.xx.xx.xx */
	*((int *) (hook_me_func + 1)) = (long) (0x9090909090909090);
}

unsigned long* afw_locate_sys_call_table(void);
static void **sys_call_table_2;
void do_syscall_64_new(struct pt_regs *regs);
void (*orig_do_syscall_64)(struct pt_regs *regs);

void do_syscall_64_new(struct pt_regs *regs) {
	// extratct table address
	orig_do_syscall_64(regs);
}

// in interrupt descriptor table
static inline u8* get_32bit_system_call_handler(void) {
	//TODO implement
	// currently not needed
	return NULL;
}

// in LSTAR MSR
static inline u8* get_64bit_system_call_handler(void) {
	u64 system_call_entry;
	rdmsrl(MSR_LSTAR, system_call_entry);
	return (u8*) system_call_entry;
}

static
unsigned long* find_sys_call_table_ref(u8* code) {
	void **do_syscall_64_kallsyms = (void*) kallsyms_lookup_name(
			"do_syscall_64");
	size_t i;
	int j;

	/* we used the same solution as the other groups, figured out the offset from the syscall routine and hardcoded it as a 
	 * magic number. That is because we couldnt get to work our solution yet. Our idea is still below:
	 */

	u32 magic_offset = 0x001e8230;

	// iterate over first 256 bytes in syscall handler
	for (i = 0; i < 256; i++) {
		if (code[i] == 0xE8) // E8 is op code for call (do_syscall_64 is first call in syscall handler)
				{
			u32 offset = *((u32*) &code[i + 1]);
			offset = offset + 5;

			// calculate twos complement
			offset = ~offset;
			offset = offset + 1;

			for (j = 0; j < 20; j++) {
				DEBUG("%p: %x",&(code[i+j]),code[i+j]);
			}

			DEBUG( "offset1 %x",offset); DEBUG("base %p",&(code[i]));

			orig_do_syscall_64 = (void*) (&(code[i]) - offset);
			DEBUG( "do_syscall_64 address: %p",orig_do_syscall_64);

			DEBUG("Syscall handling routine addresses kallsyms: %p and MSR_LSTAR %p (should be identical)",do_syscall_64_kallsyms, orig_do_syscall_64)

			break;
		}

	}
	//printk(KERN_INFO "%p",(void*)(&(code[0])+magic_offset));
	return (void*) (&(code[0]) + magic_offset);

	// this does not work YET
	/* remove write protection */
	/*	write_cr0 (read_cr0 () & (~ 0x10000));

	 x86_put_jmp(orig_do_syscall_64,(void*)do_syscall_64_new);

	 orig_do_syscall_64 = (void *)((unsigned int)orig_do_syscall_64+5);
	 msleep(500); // wait for a syscall

	 x86_remove_jmp((void *)((unsigned int)orig_do_syscall_64-5));

	 // enable write protection
	 write_cr0 (read_cr0 () | 0x10000);
	 */
	//return NULL;
}

/*
 **  And now, when everything's in place...
 */

unsigned long* afw_locate_sys_call_table(void) {
#ifdef CONFIG_X86_64
	DEBUG( "64 bit")

	return find_sys_call_table_ref(get_64bit_system_call_handler());
	/*
	 #else
	 printk(KERN_INFO "32 bit");
	 return find_sys_call_table_ref(get_32bit_system_call_handler());
	 */
#endif
}
