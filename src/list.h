#ifndef LIST_H
#define LIST_H

struct list_elem {
    struct list_elem *next;    // Zeiger auf das naechste Element
    void *data;    // Zeiger auf ein Datenobject
};

typedef struct list {
    struct list_elem *first;// erstes Element in der Liste
    struct list_elem *last;    // letztes Element in der Liste
} list_t;

/* function prototypes */
list_t *list_init(void);

struct list_elem *list_insert(list_t *list, void *data);

struct list_elem *list_append(list_t *list, void *data);

int list_remove(list_t *list, struct list_elem *elem);

int list_is_empty(list_t *liste);

void list_cleanup(list_t *list);

void list_cleanup_with_data_clean(list_t *list);

void list_print_as_int(list_t *liste);

struct list_elem *list_find(list_t *list, void *data, int (*cmp_elem)(void *, void *));

struct list_elem *list_give_nth_elem(list_t *list, int count);

#endif
