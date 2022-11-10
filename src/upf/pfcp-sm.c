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

#include "context.h"
#include "event.h"
#include "timer.h"
#include "upf-sm.h"

#include "pfcp-path.h"
#include "n4-handler.h"

static void node_timeout(ogs_pfcp_xact_t *xact, void *data);

void upf_pfcp_state_initial(ogs_fsm_t *s, upf_event_t *e) /* PFCP initial state */
{
    int rv;
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    rv = ogs_pfcp_connect(
            ogs_pfcp_self()->pfcp_sock, ogs_pfcp_self()->pfcp_sock6, node); /* Connect to pfcp node */
    ogs_assert(rv == OGS_OK);

    node->t_no_heartbeat = ogs_timer_add(ogs_app()->timer_mgr,
            upf_timer_no_heartbeat, node); /* Heartbeat timer to ckeck aliveness */
    ogs_assert(node->t_no_heartbeat);

    OGS_FSM_TRAN(s, &upf_pfcp_state_will_associate); /* Transitions to state will associate */
}

void upf_pfcp_state_final(ogs_fsm_t *s, upf_event_t *e) /* PFCP final state */
{
    ogs_pfcp_node_t *node = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    ogs_timer_delete(node->t_no_heartbeat); /* Deletes heartbeat timer */
}

void upf_pfcp_state_will_associate(ogs_fsm_t *s, upf_event_t *e)
{
    char buf[OGS_ADDRSTRLEN];

    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;
    ogs_sockaddr_t *addr = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {/* Reads node id */
    case OGS_FSM_ENTRY_SIG:
        if (node->t_association) {
            ogs_timer_start(node->t_association,
                ogs_app()->time.message.pfcp.association_interval);/* starts timer */

            ogs_pfcp_up_send_association_setup_request(node, node_timeout);/* sends association setup request */
        }
        break;

    case OGS_FSM_EXIT_SIG:
        if (node->t_association) {
            ogs_timer_stop(node->t_association); /* stops timer */
        }
        break;

    case UPF_EVT_N4_TIMER:/* timer event */
        switch(e->timer_id) {
        case UPF_TIMER_ASSOCIATION:
            addr = node->sa_list;
            ogs_assert(addr);

            ogs_warn("Retry to association with peer [%s]:%d failed",
                        OGS_ADDR(addr, buf), OGS_PORT(addr));

            ogs_assert(node->t_association);
            ogs_timer_start(node->t_association,
                ogs_app()->time.message.pfcp.association_interval);/* starts timer */

            ogs_pfcp_up_send_association_setup_request(node, node_timeout);/* send association setup request */
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_MESSAGE:/* In case event is N4 message */
        message = e->pfcp_message;/* gets message */
        ogs_assert(message);
        xact = e->pfcp_xact;
        ogs_assert(xact);

        switch (message->h.type) {
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:/* in case message is association setup request */
            ogs_pfcp_up_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            OGS_FSM_TRAN(s, upf_pfcp_state_associated);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:/* In case message is association setup response */
            ogs_pfcp_up_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            OGS_FSM_TRAN(s, upf_pfcp_state_associated);
            break;
        default:
            ogs_warn("cannot handle PFCP message type[%d]",
                    message->h.type);
            break;
        }
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_pfcp_state_associated(ogs_fsm_t *s, upf_event_t *e) /* state associated */
{
    char buf[OGS_ADDRSTRLEN];

    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;

    ogs_sockaddr_t *addr = NULL;
    upf_sess_t *sess = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;/* gets node from event */
    ogs_assert(node);
    addr = node->sa_list;/* gets socket from candidate list */
    ogs_assert(addr);

    switch (e->id) {/* depending on event id: */
    case OGS_FSM_ENTRY_SIG:
        ogs_info("PFCP associated [%s]:%d",
            OGS_ADDR(&node->addr, buf),
            OGS_PORT(&node->addr));/* associated */
        ogs_timer_start(node->t_no_heartbeat,
                ogs_app()->time.message.pfcp.no_heartbeat_duration);/* starts timer */
        break;
    case OGS_FSM_EXIT_SIG:
        ogs_info("PFCP de-associated [%s]:%d",
            OGS_ADDR(&node->addr, buf),
            OGS_PORT(&node->addr));/* de-associated */
        ogs_timer_stop(node->t_no_heartbeat);/* stops timer */
        break;
    case UPF_EVT_N4_MESSAGE:/* n4 message */
        message = e->pfcp_message;/* gets message from event */
        ogs_assert(message);
        xact = e->pfcp_xact;/* gets transaction from event */
        ogs_assert(xact);

        if (message->h.seid_presence && message->h.seid != 0)
            sess = upf_sess_find_by_upf_n4_seid(message->h.seid);/* finds session by SEID */

        switch (message->h.type) {/*depending on header type */
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_assert(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));/* handles heartbeat request (to check aliveness) */
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_assert(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));/* handles heartbeat response */
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_warn("PFCP[REQ] has already been associated [%s]:%d",
                OGS_ADDR(&node->addr, buf),
                OGS_PORT(&node->addr));
            ogs_pfcp_up_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);/* handles asscoiation setup request */
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_warn("PFCP[RSP] has already been associated [%s]:%d",
                OGS_ADDR(&node->addr, buf),
                OGS_PORT(&node->addr));
            ogs_pfcp_up_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);/* handles association setup response */
            break;
        case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
            if (message->h.seid_presence && message->h.seid == 0) {
                ogs_expect(!sess);
                sess = upf_sess_add_by_message(message);
                if (sess)
                    OGS_SETUP_PFCP_NODE(sess, node);/* If a session establishment request is received and no seid is found, adds a session giving the message and sets up a pfcp node */
            }
            upf_n4_handle_session_establishment_request(
                sess, xact, &message->pfcp_session_establishment_request);/* finally, handles the session establishment request */
            break;
        case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
            upf_n4_handle_session_modification_request(
                sess, xact, &message->pfcp_session_modification_request);/* handles the session modification request */
            break;
        case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE:
            upf_n4_handle_session_deletion_request(
                sess, xact, &message->pfcp_session_deletion_request);/* handles session deletion request */
            break;
        case OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE:
            upf_n4_handle_session_report_response(
                sess, xact, &message->pfcp_session_report_response);/* handles session report response */
            break;
        default:
            ogs_error("Not implemented PFCP message type[%d]",
                    message->h.type);
            break;
        }

        break;
    case UPF_EVT_N4_TIMER:/* timer-related events */
        switch(e->timer_id) {
        case UPF_TIMER_NO_HEARTBEAT:/* upf_timer_no_heartbeat */
            node = e->pfcp_node;
            ogs_assert(node);

            ogs_assert(OGS_OK ==
                ogs_pfcp_send_heartbeat_request(node, node_timeout));/* sends heartbeat request to check aliveness */
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_NO_HEARTBEAT:
        ogs_warn("No Heartbeat from SMF [%s]:%d",
                    OGS_ADDR(addr, buf), OGS_PORT(addr));
        OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);/* if no heartbeat from SMF is received, transition to state 'will associate' */
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_pfcp_state_exception(ogs_fsm_t *s, upf_event_t *e)/* exception state */
{
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

static void node_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    int rv;

    upf_event_t *e = NULL;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    switch (type) {/* depending on transaction type */
    case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:/* heartbeat request */
        ogs_assert(data);

        e = upf_event_new(UPF_EVT_N4_NO_HEARTBEAT);/* creates heartbeat event */
        e->pfcp_node = data;

        rv = ogs_queue_push(ogs_app()->queue, e);/* sends event to queue */
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_push() failed:%d", (int)rv);
            upf_event_free(e);
        }
        break;
    case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
        break;
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}
