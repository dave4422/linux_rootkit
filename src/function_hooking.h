#include "hook.h"
#include "list.h"
#include <linux/ftrace.h>


#define HOOK_TYPE_NONE          0
#define HOOK_TYPE_SYSCALL       1
#define HOOK_TYPE_FTRACE        2
/*
 * Structure defining a hook.
 */
typedef struct {
	atomic_t usage_count;
	const char *name;
	void *hook_function;
	/*
	 * For "ftrace" (no real ftrace used, did not work) hook this is a pointer onto a variable which
	 *  should be set on the original function plus the necessary offset for the opcode tampering:
	 * 			original_func -> local_variable -> (orig_func +5)
	 * For syscall, this pointer directly points to the original function:
	 * 			original_func -> orig_func
	 */
	void *original_function;

	unsigned int hook_type;
	unsigned long address;
	unsigned int offset;
	struct ftrace_ops ops;
} function_hook_t;


/**** Hooking list functions ****/
function_hook_t *add_function_hook_to_list(char *f_name,
		void *function, void *p_to_func_var);

function_hook_t *add_syscall_to_hook(void *hook_function,
		unsigned int offset);

void hook_functions_in_list(void);

void cleanup_function_hooking(void);

void inc_use_count(function_hook_t *hook);

void dec_use_count(function_hook_t *hook);
