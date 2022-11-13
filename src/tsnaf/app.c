
#include "ogs-app.h"
#include <stdio.h>
#include <ulfius.h>

#define PORT 8080

/**
 * Callback function for the web application on /helloworld url call
 */
int callback_hello_world (const struct _u_request * request, struct _u_response * response, void * user_data);
/**
 * Callback function for the web application on /config url call
 */
int callback_config (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_hello_world (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, "Hello World!");
  return U_CALLBACK_CONTINUE;
}

int callback_config (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, "Configuration received");
  return U_CALLBACK_CONTINUE;
}


/**
 * main function
 */
int mainREST(void);
int mainREST(void) {
  struct _u_instance instance;

  // Initialize instance with the port number
  if (ulfius_init_instance(&instance, PORT, NULL, NULL) != U_OK) {
    fprintf(stderr, "Error ulfius_init_instance, abort\n");
    return(1);
  }

  // Endpoint list declaration
  ulfius_add_endpoint_by_val(&instance, "GET", "/helloworld", NULL, 0, &callback_hello_world, NULL);
  ulfius_add_endpoint_by_val(&instance, "POST", "/config", NULL, 0, &callback_config, NULL);

  // Start the framework
  if (ulfius_start_framework(&instance) == U_OK) {
    printf("Start framework on port %d\n", instance.port);

    // Wait for the user to press <enter> on the console to quit the application
    getchar();
  } else {
    fprintf(stderr, "Error starting framework\n");
  }
  printf("End framework\n");

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);

  return 0;
}

int app_initialize(const char *const argv[])
{
    int rv;

    /*rv = upf_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to intialize UPF");
        return rv;
    }*/
    rv= mainREST();
    ogs_info("TSNAF initialize...done");

    return OGS_OK;
}

void app_terminate(void)
{
    tsnaf_terminate();
    ogs_info("UPF terminate...done");
}



