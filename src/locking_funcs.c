#include "hook.h"


/* increment counter of a critical section */
void inc_critical(struct mutex *lock, int *counter)
{
	/* lock access mutex */
	mutex_lock(lock);
	(*counter)++;

	/* unlock access mutex */
	mutex_unlock(lock);
}

/* decrement counter of a critical section */
void dec_critical(struct mutex *lock, int *counter)
{

	/* lock access mutex */
	mutex_lock(lock);
	(*counter)--;

	/* unlock access mutex */
	mutex_unlock(lock);
}
