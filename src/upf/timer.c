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

#include "timer.h"
#include "event.h"
#include "context.h"

const char *upf_timer_get_name(upf_timer_e id) //Returns timer name given an UPF timer enum
{
    switch (id) {
    case UPF_TIMER_ASSOCIATION:
        return "UPF_TIMER_ASSOCIATION";
    case UPF_TIMER_NO_HEARTBEAT:
        return "UPF_TIMER_NO_HEARTBEAT";
    default: 
       break;
    }

    return "UNKNOWN_TIMER";
}

static void timer_send_event(int timer_id, void *data) //Creates a new timer event and sends it to queue
{
    int rv;
    upf_event_t *e = NULL;
    ogs_assert(data);

    e = upf_event_new(UPF_EVT_N4_TIMER);
    e->timer_id = timer_id;
    e->pfcp_node = data;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        upf_event_free(e);
    }
}

void upf_timer_association(void *data) //Associates a timer to pfcp node
{
    timer_send_event(UPF_TIMER_ASSOCIATION, data);
}

void upf_timer_no_heartbeat(void *data) //Associates a timer of no heartbeat to pfcp node
{
    timer_send_event(UPF_TIMER_NO_HEARTBEAT, data);
}
