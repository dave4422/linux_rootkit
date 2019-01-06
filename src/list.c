#include "list.h"
#include "hook.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>

list_t *list_init() {
    list_t *ret;
    ret = kmalloc(sizeof(list_t), GFP_KERNEL);
    ret->first = NULL;
    ret->last = NULL;
    return ret;
}

struct list_elem *list_insert(list_t *list, void *data) {
    struct list_elem *ret;
    ret = kmalloc(sizeof(struct list_elem), GFP_KERNEL);
    ret->data = data;
    ret->next = list->first;
    list->first = ret;
    if(list->last == NULL){
        list->last = ret;
    }
    return ret;
}

struct list_elem *list_append(list_t *list, void *data) {
    struct list_elem *ret;
    ret = kmalloc(sizeof(struct list_elem), GFP_KERNEL);
    ret->data = data;
    if (list->last != NULL) {
        list->last->next = ret;
    }
    list->last = ret;
    ret->next = NULL;
    if(list->first == NULL){
        list->first = ret;
    }
    return ret;
}

int list_is_empty(list_t *liste){
	if(liste->first == NULL){
		return 1;
	}
	return 0;
}

int list_remove(list_t *list, struct list_elem *elem) {
    if(elem == NULL){
        return -1;
    }
    struct list_elem *tmp = list->first;
    if (tmp == elem) {
        list->first = tmp->next;
        if (tmp == list->last) {
            list->last = NULL;
        }
        kfree(tmp);
        return 0;
    }
    while (tmp->next != elem && tmp != NULL) {
        tmp = tmp->next;
    }
    if (tmp == NULL) {
        return -1;
    }
    if (tmp->next->next == NULL) {
        list->last = tmp;
    }
    tmp->next = tmp->next->next;
    kfree(elem);
    return 0;
}

void list_print_as_int(list_t *liste){
	struct list_elem *first;
	int numbering = 1;
	int *print_me;
	first = liste->first;
	while(first != NULL){
		print_me = (int *)first->data;
		printk(KERN_INFO "list elem nr. %d is %d", numbering, *print_me);
		numbering++;
		first = first->next;
	}
}

void list_cleanup(list_t *list) {
    struct list_elem *tmp = list->first;
    struct list_elem *tmp2;
    while (tmp != NULL) {
        tmp2 = tmp->next;
        kfree(tmp);
        tmp = tmp2;
    }

	kfree(list);
}

/**
 * Not only cleans list but also frees data pointer of the list.
 */
void list_cleanup_with_data_clean(list_t *list) {
	if(list == NULL){
		return;
	}
    struct list_elem *tmp = list->first;
    struct list_elem *tmp2;
    while (tmp != NULL) {
        tmp2 = tmp->next;
        if(tmp->data != NULL){
            kfree(tmp->data);
        }
        kfree(tmp);
        tmp = tmp2;
    }

	kfree(list);
}

struct list_elem *list_give_nth_elem(list_t *list, int count){
    int c;
    struct list_elem *ret;
    if(count < 0){
        return NULL;
    }
    ret = list->first;
    if(ret == NULL){
        return NULL;
    }
    c = 0;
    while(c < count){
        if(ret->next != NULL){
            ret = ret->next;
        }
        else{
            return NULL;
        }
        c++;
    }
    return ret;
}

struct list_elem *list_find(list_t *list, void *data, int (*cmp_elem)(void *, void *)) {
    struct list_elem *tmp = list->first;
    while (tmp != NULL) {
        if (!cmp_elem(data, tmp->data)) {
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}
