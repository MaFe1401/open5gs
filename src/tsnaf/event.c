#include "event.h"
#include "context.h"

static OGS_POOL(pool, tsnaf_event_t);

void tsnaf_event_term(void) //Terminate event queue
{
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void tsnaf_event_final(void) //Release resources
{
    ogs_pool_final(&pool);
}