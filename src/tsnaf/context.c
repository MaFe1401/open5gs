
#include "sbi-path.h"
#include "ogs-app.h"
#include "ogs-crypt.h"
#include "ogs-sbi.h"
#include "context.h"


static tsnaf_context_t self;

int __tsnaf_log_domain;


//static OGS_POOL(tsnaf_ue_pool, tsn_ue_t);
static OGS_POOL(tsnaf_sess_pool, tsnaf_sess_t); //Definir tsnaf_sess_s
static int context_initialized = 0;

void tsnaf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize TSNAF context */
    memset(&self, 0, sizeof(tsnaf_context_t));

    
    ogs_log_install_domain(&__tsnaf_log_domain, "tsnaf", ogs_core()->log.level);

    
    ogs_pool_init(&tsnaf_sess_pool, ogs_app()->pool.sess);
    
    self.ipv4addr_hash = ogs_hash_make();
    ogs_assert(self.ipv4addr_hash);
    self.ipv6prefix_hash = ogs_hash_make();
    ogs_assert(self.ipv6prefix_hash);

    context_initialized = 1;
}

int tsnaf_context_prepare(void){
    return OGS_OK;
}

int tsnaf_context_validation(void){
    return OGS_OK;
}

int tsnaf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = tsnaf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "tsnaf")) {
            ogs_yaml_iter_t tsnaf_iter;
            ogs_yaml_iter_recurse(&root_iter, &tsnaf_iter);
            while (ogs_yaml_iter_next(&tsnaf_iter)) {
                const char *tsnaf_key = ogs_yaml_iter_key(&tsnaf_iter);
                ogs_assert(tsnaf_key);
                if (!strcmp(tsnaf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tsnaf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(tsnaf_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", tsnaf_key);
            }
        }
    }

    rv = tsnaf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

void tsnaf_context_final(void) //Remove session, hashes...
{
    ogs_assert(context_initialized == 1);

    //tsnaf_sess_remove_all();

    
    ogs_assert(self.ipv4addr_hash);
    ogs_hash_destroy(self.ipv4addr_hash);
    ogs_assert(self.ipv6prefix_hash);
    ogs_hash_destroy(self.ipv6prefix_hash);

    ogs_pool_final(&tsnaf_sess_pool);

    context_initialized = 0;
}
/*static void clear_ipv4addr(tsnaf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->ipv4addr_string) {
        ogs_hash_set(self.ipv4addr_hash,
                &sess->ipv4addr, sizeof(sess->ipv4addr), NULL);
        ogs_free(sess->ipv4addr_string);
    }
}

static void clear_ipv6prefix(tsnaf_sess_t *sess)
{
    ogs_assert(sess);

    if (sess->ipv6prefix_string) {
        ogs_hash_set(self.ipv6prefix_hash,
                &sess->ipv6prefix, (sess->ipv6prefix.len >> 3) + 1, NULL);
        ogs_free(sess->ipv6prefix_string);
    }
} tsnaf_sess_s is undefined */ 