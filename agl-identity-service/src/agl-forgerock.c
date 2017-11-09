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

#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 2
#include <afb/afb-binding.h>

#include "oidc-agent.h"
#include "aia-get.h"

static int expiration_delay = 5;

static const char default_endpoint[] = "https://agl-graphapi.forgerocklabs.org/getuserprofilefromtoken";
static const char *oidc_name;

static char *endpoint;

static void (*onloaded)(struct json_object *data, const char *error);

/***** configuration ********************************************/

static void confsetstr(struct json_object *conf, const char *name, char **value, const char *def)
{
	struct json_object *v;
	const char *s;
	char *p;

	s = conf && json_object_object_get_ex(conf, name, &v) ? json_object_get_string(v) : def;
	p = *value;
	if (s && p != s) {
		*value = strdup(s);
		free(p);
	}
}

static void confsetint(struct json_object *conf, const char *name, int *value, int def)
{
	struct json_object *v;

	*value = conf && json_object_object_get_ex(conf, name, &v) ? json_object_get_int(v) : def;
}

static void confsetoidc(struct json_object *conf, const char *name)
{
	struct json_object *idp, *appli;

	if (conf
	 && json_object_object_get_ex(conf, "idp", &idp)
	 && json_object_object_get_ex(conf, "appli", &appli)) {
		if (oidc_idp_set(name, idp) && oidc_appli_set(name, name, appli, 1)) {
			oidc_name = name;
		}
	}
}

/****************************************************************/

static void loaded(struct json_object *data, const char *error)
{
	if (onloaded)
		onloaded(data, error);
}

static void downloaded(void *closure, int status, const void *buffer, size_t size)
{
	struct json_object *object, *subobj;
	char *url = closure;

	/* checks whether discarded */
	if (status == 0 && !buffer) {
		AFB_ERROR("discarded");
		loaded(NULL, "discarded");
		goto end; /* discarded */
	}

	/* scan for the status */
	if (status == 0 || !buffer) {
		AFB_ERROR("uploading %s failed %s", url ? : "?", (const char*)buffer ? : "");
		loaded(NULL, "failed");
		goto end;
	}

	/* get the object */
	AFB_DEBUG("received data: %.*s", (int)size, (char*)buffer);
	object = json_tokener_parse(buffer); /* okay because 0 appended */

	/* extract useful part */
	subobj = NULL;
	if (object && !json_object_object_get_ex(object, "results", &subobj))
		subobj = NULL;
	if (subobj)
		subobj = json_object_array_get_idx(subobj, 0);
	if (subobj && !json_object_object_get_ex(subobj, "data", &subobj))
		subobj = NULL;
	if (subobj)
		subobj = json_object_array_get_idx(subobj, 0);
	if (subobj && !json_object_object_get_ex(subobj, "row", &subobj))
		subobj = NULL;
	if (subobj)
		subobj = json_object_array_get_idx(subobj, 0);

	/* is it a recognized user ? */
	if (!subobj) {
		/* not recognized!! */
		AFB_INFO("unrecognized key for %s", url ? : "?");
		json_object_put(object);
		loaded(NULL, "malformed");
		goto end;
	}

	loaded(subobj, NULL);
	json_object_put(object);
end:
	free(url);
}

/** public **************************************************************/

void agl_forgerock_setconfig(struct json_object *conf)
{
	confsetstr(conf, "endpoint", &endpoint, endpoint ? : default_endpoint);
	confsetint(conf, "delay", &expiration_delay, expiration_delay);
	confsetoidc(conf, "oidc-aia");
	AFB_NOTICE("Forgerock endpoint is: %s", endpoint);
}

void agl_forgerock_setcb(void (*callback)(struct json_object *data, const char *error))
{
	onloaded = callback;
}

void agl_forgerock_download_request(const char *vin, const char *kind, const char *key)
{
	int rc;
	char *url;

	rc = asprintf(&url, "%s?vin=%s&kind=%s&keytoken=%s", endpoint, vin, kind, key);
	if (rc >= 0)
		aia_get(url, expiration_delay, oidc_name, oidc_name, downloaded, url);
	else
		AFB_ERROR("out of memory");
}

/* vim: set colorcolumn=80: */

