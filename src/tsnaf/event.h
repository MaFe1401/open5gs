#ifndef TSNAF_EVENT_H
#define TSNAF_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tsnaf_sess_s tsnaf_sess_t;

typedef struct tsnaf_event_s {
    ogs_event_t h;

    tsnaf_sess_t *sess;
    
} tsnaf_event_t;

/*tsnaf_event_t *tsnaf_event_new(int id);*/

//const char *tsnaf_event_get_name(tsnaf_event_t *e);

void tsnaf_event_term(void);

void tsnaf_event_final(void); //Release resources

#ifdef __cplusplus
}
#endif

#endif /* TSNAF_EVENT_H */