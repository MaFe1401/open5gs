#include "sbi-path.h"
#include "context.h"
#include "event.h"
#include "ogs-app.h"

static ogs_thread_t *thread;
static void tsnaf_main(void *data);
static int initialized = 0;

int tsnaf_initialize()
{
    int rv;

    ogs_sbi_context_init();

    tsnaf_context_init();

    rv = ogs_sbi_context_parse_config("tsnaf", "nrf", "scp");
    if (rv != OGS_OK) return rv;

    rv = tsnaf_context_parse_config();
    if (rv != OGS_OK) return rv;

    //rv = ogs_dbi_init(ogs_app()->db_uri);
    //if (rv != OGS_OK) return rv;

    rv = tsnaf_sbi_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(tsnaf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

void tsnaf_terminate(void)
{
    if (!initialized) return;

    tsnaf_event_term();

    ogs_thread_destroy(thread);

    tsnaf_context_final();

    tsnaf_event_final();

    tsnaf_sbi_close();

    ogs_sbi_context_final();
}

static void tsnaf_main(void *data){
    
}