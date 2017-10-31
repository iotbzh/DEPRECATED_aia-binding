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


#pragma once

struct aia_uds_value
{
	const char *data;
	size_t length;
	int changed;
};

struct aia_uds
{
	struct aia_uds_value first_name;
	struct aia_uds_value last_name;
	struct aia_uds_value email;
	struct aia_uds_value language;
};

typedef void (*aia_uds_on_change)(const struct aia_uds *);

extern aia_uds_on_change aia_uds_set_on_change(aia_uds_on_change callback);

extern int aia_uds_activate(int onoff, void (*callback)(void *closure, int error, int state), void *closure);

extern int aia_uds_advise(int onoff, void (*callback)(void *closure, int error, int state), void *closure);

extern int aia_uds_init(struct sd_bus *bus);

