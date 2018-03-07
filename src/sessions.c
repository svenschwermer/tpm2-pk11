/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2017 Iwan Timmer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "sessions.h"

#include <stdlib.h>

#ifdef TCTI_SOCKET_ENABLED
#include <tcti/tcti_socket.h>
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
#include <tcti/tcti_device.h>
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
#include <tcti/tcti-tabrmd.h>
#endif // TCTI_TABRMD_ENABLED

#define DEFAULT_DEVICE "/dev/tpm0"
#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 2323

unsigned int open_sessions;

int session_init(struct session* session, struct config *config) {
  session->context = NULL;

  size_t size = 0;
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  TSS2_RC rc;

  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET:
      rc = Tss2_Tcti_Socket_Init(NULL, &size, NULL);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE:
      rc = Tss2_Tcti_Device_Init(NULL, &size, NULL);
      break;
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = tss2_tcti_tabrmd_init(NULL, &size);
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;

  tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
  if (tcti_ctx == NULL)
    goto cleanup;

  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET: {
      const char *hostname = config->hostname != NULL ? config->hostname : DEFAULT_HOSTNAME;
      unsigned int port = config->port > 0 ? config->port : DEFAULT_PORT;
      size_t buffer_len = strlen(hostname) + 20;
      const char *conf = calloc(1, buffer_len);
      if (conf == NULL)
        goto cleanup;
      snprintf(conf, buffer_len, "tcp://%s:%u", hostname, port);
      rc = Tss2_Tcti_Socket_Init(tcti_ctx, &size, conf);
      free(conf);
      break;
    }
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE: {
      const char *conf = config->device != NULL ? config->device : DEFAULT_DEVICE;
      rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, conf);
      break;
    }
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = tss2_tcti_tabrmd_init(tcti_ctx, &size);
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;
  
  size = Tss2_Sys_GetContextSize(0);
  session->context = (TSS2_SYS_CONTEXT*) calloc(1, size);
  if (session->context == NULL)
    goto cleanup;

  TSS2_ABI_VERSION abi_version = {
    .tssCreator = TSSWG_INTEROP,
    .tssFamily = TSS_SAPI_FIRST_FAMILY,
    .tssLevel = TSS_SAPI_FIRST_LEVEL,
    .tssVersion = TSS_SAPI_FIRST_VERSION,
  };
  rc = Tss2_Sys_Initialize(session->context, size, tcti_ctx, &abi_version);

  session->objects = object_load(session->context, config);
  open_sessions++;

  return 0;

  cleanup:
  if (tcti_ctx != NULL)
    free(tcti_ctx);

  if (session->context != NULL)
    free(session->context);

  return -1;
}

void session_close(struct session* session) {
  object_free(session->objects);
  Tss2_Sys_Finalize(session->context);
  open_sessions--;
}
