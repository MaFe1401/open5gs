#include "sbi-path.h"

int tsnaf_sbi_open(void){
     return OGS_OK;
}
 
void tsnaf_sbi_close(void)
{
    ogs_sbi_client_stop_all();
    ogs_sbi_server_stop_all();
}