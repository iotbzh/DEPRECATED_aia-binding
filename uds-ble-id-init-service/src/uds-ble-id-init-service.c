/*
 * Copyright (C) 2015, 2016, 2017 "IoT.bzh"
 * Author: José Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <json-c/json.h>
#include <systemd/sd-bus.h>

#define AFB_BINDING_VERSION 2
#include <afb/afb-binding.h>

#include "aia-uds-bluez.h"

#if !defined(AUTO_START_ADVISE)
#define AUTO_START_ADVISE 1
#endif

static int advising;

static struct afb_event event;

static int autoadvise = AUTO_START_ADVISE;

/****************************************************************/

static void on_uds_change(const struct aia_uds *uds)
{
	struct json_object *object;

	AFB_INFO("UDS changed"
		" first-name%s[%.*s]"
		" last-name%s[%.*s]"
		" email%s[%.*s]"
		" language%s[%.*s]",
		uds->first_name.changed ? "*" : "", (int)uds->first_name.length, uds->first_name.data ?:"",
		uds->last_name.changed ? "*" : "", (int)uds->last_name.length, uds->last_name.data ?:"",
		uds->email.changed ? "*" : "", (int)uds->email.length, uds->email.data ?:"",
		uds->language.changed ? "*" : "", (int)uds->language.length, uds->language.data ?:"");

	if (uds->email.changed) {
		object = json_object_new_object();
		json_object_object_add(object, "incoming", json_object_new_string(uds->email.data));
		afb_event_push(event, object);
	}
}

static void start (struct afb_req request)
{
	int rc;

	if (!advising) {
		rc = aia_uds_advise(1, NULL, NULL);
		if (rc < 0) {
/*
TODO: solve the issue
			afb_req_fail(request, "failed", "start scan failed");
			return;
*/
			AFB_ERROR("Ignoring scan start failed, because probably already in progress");
		}
	}
	advising = advising + 1;
	afb_req_subscribe(request, event);
	afb_req_success(request, NULL, NULL);
}


static void stop (struct afb_req request)
{
	if (advising) {
		advising = advising - 1;
		if (!advising)
			aia_uds_advise(0, NULL, NULL);
	}
	afb_req_success(request, NULL, NULL);
}

static int init()
{
	sd_bus *bus;
	int rc;

	bus = afb_daemon_get_system_bus();
	rc = bus ? aia_uds_init(bus) : -ENOTSUP;	
	if (rc < 0) {
		errno = -rc;
		return -1;
	}

	aia_uds_set_on_change(on_uds_change);

	event = afb_daemon_make_event("event");
	if (!afb_event_is_valid(event))
		return -1;

	rc = aia_uds_advise(autoadvise, NULL, NULL);
	advising = autoadvise && rc >= 0;
	return rc < 0 ? rc : 0;
}


// NOTE: this sample does not use session to keep test a basic as possible
//     in real application most APIs should be protected with AFB_SESSION_CHECK
static const struct afb_verb_v2 verbs[]=
{
  {"start"  , start, NULL, "start User Data Service", AFB_SESSION_NONE },
  {"stop"   , stop , NULL, "stop User Data Service" , AFB_SESSION_NONE },
  {NULL}
};

const struct afb_binding_v2 afbBindingV2 =
{
	.api = "uds-ble-init-id",
	.specification = NULL,
	.info = "AGL Identitity initiator above BLE's User Data Service",
	.verbs = verbs,
	.preinit = NULL,
	.init = init,
	.onevent = NULL,
	.noconcurrency = 1
};

/* vim: set colorcolumn=80: */

