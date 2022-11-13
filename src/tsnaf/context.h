#include "ogs-app.h"
#include "ogs-crypt.h"
#include "ogs-sbi.h"


typedef struct tsnaf_context_s {
    ogs_hash_t      *ipv4addr_hash;
    ogs_hash_t      *ipv6prefix_hash;
} tsnaf_context_t;

typedef struct tsnaf_sess_s { 

}tsnaf_sess_t;
void tsnaf_context_final(void);

int tsnaf_context_parse_config(void);

int tsnaf_context_validation(void);

int tsnaf_context_prepare(void);

void tsnaf_context_init(void);