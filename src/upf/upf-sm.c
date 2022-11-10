/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "upf-sm.h"
#include "context.h"
#include "event.h"
#include "pfcp-path.h"
#include "gtp-path.h"

/* Finite State Machine */
void upf_state_initial(ogs_fsm_t *s, upf_event_t *e) /* Transitions to operational */
{
    upf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &upf_state_operational);
}

void upf_state_final(ogs_fsm_t *s, upf_event_t *e) /* final */
{
    upf_sm_debug(e);

    ogs_assert(s);
}

void upf_state_operational(ogs_fsm_t *s, upf_event_t *e) /* Arguments: A state and an event */
{
    int rv;
    ogs_pkbuf_t *recvbuf = NULL; /* Reception buffer */

    ogs_pfcp_message_t pfcp_message; /* PFCP message */
    ogs_pfcp_node_t *node = NULL; /* PFCP node */
    ogs_pfcp_xact_t *xact = NULL; /* PFCP transaction */

    upf_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {/* Reads event id */
    case OGS_FSM_ENTRY_SIG:
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    case UPF_EVT_N4_MESSAGE:/* In case event is N4 message */
        ogs_assert(e);
        recvbuf = e->pkbuf;/* receives buffer from event */
        ogs_assert(recvbuf);
        node = e->pfcp_node;/* Reads pfcp node */
        ogs_assert(node);

        if (ogs_pfcp_parse_msg(&pfcp_message, recvbuf) != OGS_OK) {/* Parses PFCP message */
            ogs_error("ogs_pfcp_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        rv = ogs_pfcp_xact_receive(node, &pfcp_message.h, &xact); /* Receives transaction */
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        e->pfcp_message = &pfcp_message; /* Assigns pfcp message */
        e->pfcp_xact = xact; /* Assigns pfcp transaction to event */
        ogs_fsm_dispatch(&node->sm, e); /* Changes state */
        if (OGS_FSM_CHECK(&node->sm, upf_pfcp_state_exception)) {
            ogs_error("PFCP state machine exception");
            break;
        }

        ogs_pkbuf_free(recvbuf);
        break;
    case UPF_EVT_N4_TIMER:
    case UPF_EVT_N4_NO_HEARTBEAT: /* In case event is N4 heartbeat */
        node = e->pfcp_node;
        ogs_assert(node);
        ogs_assert(OGS_FSM_STATE(&node->sm));

        ogs_fsm_dispatch(&node->sm, e);
        break;
    default:
        ogs_error("No handler for event %s", upf_event_get_name(e));
        break;
    }
}
