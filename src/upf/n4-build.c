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
#include "n4-build.h"

ogs_pkbuf_t *upf_n4_build_session_establishment_response(uint8_t type,
    upf_sess_t *sess, ogs_pfcp_pdr_t *created_pdr[], int num_of_created_pdr) /*Determines PFCP node ID and includes created PDRs in the response*/
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_session_establishment_response_t *rsp = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    int i = 0, j = 0;

    ogs_pfcp_node_id_t node_id;
    ogs_pfcp_f_seid_t f_seid;
    int len = 0;

    ogs_debug("Session Establishment Response");

    rsp = &pfcp_message.pfcp_session_establishment_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t)); //Empty pfcp message

    /* Node ID */ /*Determines a PFCP node ID and includes it in the session establishment response*/
    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_app()->parameter.prefer_ipv4,
            &node_id, &len);
    rsp->node_id.presence = 1;
    rsp->node_id.data = &node_id;
    rsp->node_id.len = len;

    /* Cause */
    rsp->cause.presence = 1;
    rsp->cause.u8 = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    /* F-SEID */ /* Determines FSEID given IP addresses */
    ogs_pfcp_sockaddr_to_f_seid(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            &f_seid, &len);
    f_seid.seid = htobe64(sess->upf_n4_seid);
    rsp->up_f_seid.presence = 1;
    rsp->up_f_seid.data = &f_seid;
    rsp->up_f_seid.len = len;

    ogs_pfcp_pdrbuf_init();

    /* Created PDR */ /* Created pdr will contain all the pdrs. Each created PDR in the response contains an FTEID (IP + teid) which identifies the logical tunnel */
    for (i = 0, j = 0; i < num_of_created_pdr; i++) {
        bool pdr_presence = ogs_pfcp_build_created_pdr(
                &rsp->created_pdr[j], i, created_pdr[i]);
        if (pdr_presence == true) j++;
    }

    pfcp_message.h.type = type;
    pkbuf = ogs_pfcp_build_msg(&pfcp_message);

    ogs_pfcp_pdrbuf_clear();

    return pkbuf;
}

ogs_pkbuf_t *upf_n4_build_session_modification_response(uint8_t type,
    upf_sess_t *sess, ogs_pfcp_pdr_t *created_pdr[], int num_of_created_pdr) /* Now node id and FSEID are not included in the response. type example: OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE; */
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_session_modification_response_t *rsp = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    int i = 0, j = 0;

    ogs_debug("Session Modification Response");

    rsp = &pfcp_message.pfcp_session_modification_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    /* Cause */
    rsp->cause.presence = 1;
    rsp->cause.u8 = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    ogs_pfcp_pdrbuf_init();

    /* Created PDR */
    for (i = 0, j = 0; i < num_of_created_pdr; i++) {
        bool pdr_presence = ogs_pfcp_build_created_pdr(
                &rsp->created_pdr[j], i, created_pdr[i]);
        if (pdr_presence == true) j++;
    }

    pfcp_message.h.type = type;
    pkbuf = ogs_pfcp_build_msg(&pfcp_message);

    ogs_pfcp_pdrbuf_clear();

    return pkbuf;
}

ogs_pkbuf_t *upf_n4_build_session_deletion_response(uint8_t type,
        upf_sess_t *sess) /* Builds the session deletion response and includes the reports for each URR*/
{
    ogs_pfcp_urr_t *urr = NULL;
    ogs_pfcp_user_plane_report_t report;
    size_t num_of_reports = 0;
    ogs_debug("Session Deletion Response");

    memset(&report, 0, sizeof(report));
    ogs_list_for_each(&sess->pfcp.urr_list, urr) {
        ogs_assert(num_of_reports < OGS_ARRAY_SIZE(report.usage_report));
        upf_sess_urr_acc_fill_usage_report(sess, urr, &report, num_of_reports);
        report.usage_report[num_of_reports].rep_trigger.termination_report = 1;
        num_of_reports++;
        upf_sess_urr_acc_snapshot(sess, urr);
    }
    report.num_of_usage_report = num_of_reports;

    return ogs_pfcp_build_session_deletion_response(type, OGS_PFCP_CAUSE_REQUEST_ACCEPTED,
                                                    &report);
}
