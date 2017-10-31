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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <systemd/sd-bus.h>

#include "aia-uds-bluez.h"

#define ROOT	"/uds"

#define ITF_SERVICE		"org.bluez.GattService1"
#define ITF_CHARACTERISTIC	"org.bluez.GattCharacteristic1"
#define ITF_DESCRIPTOR		"org.bluez.GattDescriptor1"

/****** internal types **********/

struct item
{
	const char *uuid;
	const char *path;
	struct item *parent;
	struct aia_uds_value *value;
};

/****** internal data **********/

static sd_bus *busini;
static int activation;

static aia_uds_on_change on_change_callback;

static struct aia_uds uds;

static struct aia_uds uds_descs = 
{
	.first_name = { .data = "First name of the user" },
	.last_name = { .data = "Last name of the user" },
	.email = { .data = "Email of the user" },
	.language = { .data = "The Language definition is based on ISO639-1" }
};

static struct aia_uds_value woutf8 = { .data = "\031\000\047\000\001\000\000", .length = 7 };

static struct item services[1] =
{
	{
		.uuid = "0000181C-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0"
	}
};

static struct item characteristics[4] =
{
	{
		.uuid = "00002A8A-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char0",
		.parent = &services[0],
		.value = &uds.first_name
	}, {
		.uuid = "00002A90-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char1",
		.parent = &services[0],
		.value = &uds.last_name
	}, {
		.uuid = "00002A87-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char2",
		.parent = &services[0],
		.value = &uds.email
	}, {
		.uuid = "00002AA2-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char3",
		.parent = &services[0],
		.value = &uds.language
	}
};

static struct item descriptors[8] =
{
	{
		.uuid = "00002901-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char0/desc0",
		.parent = &characteristics[0],
		.value = &uds_descs.first_name
	}, {
		.uuid = "00002904-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char0/desc1",
		.parent = &characteristics[0],
		.value = &woutf8
	}, {
		.uuid = "00002901-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char1/desc0",
		.parent = &characteristics[1],
		.value = &uds_descs.last_name
	}, {
		.uuid = "00002904-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char1/desc1",
		.parent = &characteristics[1],
		.value = &woutf8
	}, {
		.uuid = "00002901-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char2/desc0",
		.parent = &characteristics[2],
		.value = &uds_descs.email
	}, {
		.uuid = "00002904-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char2/desc1",
		.parent = &characteristics[2],
		.value = &woutf8
	}, {
		.uuid = "00002901-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char3/desc0",
		.parent = &characteristics[3],
		.value = &uds_descs.language
	}, {
		.uuid = "00002904-0000-1000-8000-00805f9b34fb",
		.path = ROOT"/service0/char3/desc1",
		.parent = &characteristics[3],
		.value = &woutf8
	}
};

/****** utility ***********/

static uint16_t get_offset(sd_bus_message *m)
{
	uint16_t offset;
	const char *key;

	if (0 < sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv")) {
		while (sd_bus_message_read_basic(m, 's', &key) > 0) {
			if (strcmp(key,"offset"))
				sd_bus_message_skip(m, "v");
			else {
				if (sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "q")) {
					sd_bus_message_read_basic(m, 'q', &offset);
					sd_bus_message_exit_container(m);
					return offset;
				}
			}
		}
		sd_bus_message_exit_container(m);
	}
	return 0;
}

static int message_append_strings(sd_bus_message *m, const char **s)
{
	int rc = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "s");
	while (rc >= 0 && *s)
		rc = sd_bus_message_append_basic(m, 's', *s++);
	if (rc >= 0)
		rc = sd_bus_message_close_container(m);
	return rc;
}

/****** common callbacks ***********/

static int get_uuid(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	struct item *item = userdata;
	return sd_bus_message_append_basic(reply, 's', item->uuid);
}

static int get_parent(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	struct item *item = userdata;
	return sd_bus_message_append_basic(reply, 'o', item->parent->path);
}

static int get_children(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	size_t i, n;
	int rc;

	rc = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "o");
	n = sizeof characteristics / sizeof *characteristics;
	i = 0;
	while (rc >= 0 && i < n) {
		if (characteristics[i].parent == userdata)
			rc = sd_bus_message_append_basic(reply, 'o', characteristics[i].path);
		i++;
	}
	n = sizeof descriptors / sizeof *descriptors;
	i = 0;
	while (rc >= 0 && i < n) {
		if (descriptors[i].parent == userdata)
			rc = sd_bus_message_append_basic(reply, 'o', descriptors[i].path);
		i++;
	}
	if (rc >= 0)
		rc = sd_bus_message_close_container(reply);
	return rc;
}

static int read_value_offset(
		struct item *item,
		size_t offset,
		sd_bus_message *reply)
{
	struct aia_uds_value *value = item->value;
	const char *data = value ? value->data : NULL;
	size_t size = !value ? 0 : value->length ? value->length : data ? strlen(data) : 0;
	return sd_bus_message_append_array(reply, 'y', &data[offset], offset > size ? 0 : size - offset);
}

static int read_value(
		sd_bus_message *m,
		void *userdata,
		sd_bus_error *ret_error)
{
	int rc;
	sd_bus_message *r;

	rc = sd_bus_message_new_method_return(m, &r);
	rc = read_value_offset(userdata, get_offset(m), r);
	rc = sd_bus_send(NULL, r, NULL);
	return 1;
}

static int write_value_offset(
		struct item *item,
		size_t offset,
		const char *buffer,
		size_t length)
{
	struct aia_uds_value *value = item->value;
	const char *data = value ? value->data : NULL;
	size_t size = !value ? 0 : value->length ? value->length : data ? strlen(data) : 0;


	char *next = malloc(offset + length + 1);
	if (!next)
		return -ENOMEM;
	if (offset) {
		if (size >= offset)
			memcpy(next, data, offset);
		else {
			memcpy(next, data, size);
			memset(&next[size], 0, offset - size);
		}
	}
	memcpy(&next[offset], buffer, length);
	next[offset + length] = 0;
	value->data = next;
	value->length = offset + length;
	free((char*)data);

	return 0;
}

static int write_value(
		sd_bus_message *m,
		void *userdata,
		sd_bus_error *ret_error)
{
	int rc;
	struct item *item = userdata;
	const void *data;
	size_t size;
	sd_bus_message *r;

	rc = sd_bus_message_read_array(m, 'y', &data, &size);
	rc = write_value_offset(item, get_offset(m), data, size);

	rc = sd_bus_message_new_method_return(m, &r);
	rc = sd_bus_send(NULL, r, NULL);

	sd_bus_emit_properties_changed(sd_bus_message_get_bus(m), item->path, ITF_CHARACTERISTIC, "Value", NULL);

	if (on_change_callback) {
		item->value->changed = 1;
		on_change_callback(&uds);
		item->value->changed = 0;
	}

	return 1;
}

static int get_value(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	return read_value_offset(userdata, 0, reply);
}

static int get_true(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	int v = 1;
	return sd_bus_message_append_basic(reply, 'b', &v);
}

static int get_false(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	int v = 0;
	return sd_bus_message_append_basic(reply, 'b', &v);
}

static int not_supported(
		sd_bus_message *m,
		void *userdata,
		sd_bus_error *ret_error)
{
	return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotSupported", "not supported");
}

static int not_permitted(
		sd_bus_message *m,
		void *userdata,
		sd_bus_error *ret_error)
{
	return sd_bus_reply_method_errorf(m, "org.bluez.Error.NotPermitted", "not permitted");
}

static int failed(
		sd_bus_message *m,
		void *userdata,
		sd_bus_error *ret_error)
{
	return sd_bus_reply_method_errorf(m, "org.bluez.Error.Failed", "failed");
}

/****** service's callbacks ***********/

static int get_srv_includes(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	int rc = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "o");
	if (rc >= 0)
		rc = sd_bus_message_close_container(reply);
	return rc;
}

/****** characteristic's callbacks ***********/

static int get_char_flags(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	static const char *flags[] = { "read", "write", NULL };
	return message_append_strings(reply, flags);
}

/****** descriptor's callbacks ***********/

static int get_desc_flags(
		struct sd_bus *bus,
		const char *path,
		const char *interface,
		const char *property,
		sd_bus_message *reply,
		void *userdata,
		sd_bus_error *ret_error)
{
	static const char *flags[] = { "read", NULL };
	return message_append_strings(reply, flags);
}

/****** description ***********/

static struct sd_bus_vtable vservice[] = {
	SD_BUS_VTABLE_START(0),

	SD_BUS_PROPERTY("UUID", "s", get_uuid, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Primary", "b", get_true, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Includes", "ao", get_srv_includes, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Characteristics", "ao", get_children, 0, SD_BUS_VTABLE_PROPERTY_CONST),

	SD_BUS_VTABLE_END
};


static struct sd_bus_vtable vcharacteristic[] = {
	SD_BUS_VTABLE_START(0),

	SD_BUS_METHOD("ReadValue", "a{sv}", "ay", read_value, 0),
	SD_BUS_METHOD("WriteValue", "aya{sv}", "", write_value, 0),
	SD_BUS_METHOD("StartNotify", "", "", not_supported, 0),
	SD_BUS_METHOD("StopNotify", "", "", failed, 0),

	SD_BUS_PROPERTY("UUID", "s", get_uuid, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Service", "o", get_parent, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Value", "ay", get_value, 0, 0),
	SD_BUS_PROPERTY("WriteAcquired", "b", get_false, 0, 0),
	SD_BUS_PROPERTY("NotifyAcquired", "b", get_false, 0, 0),
	SD_BUS_PROPERTY("Notifying", "b", get_false, 0, 0),
	SD_BUS_PROPERTY("Flags", "as", get_char_flags, 0, 0),
	SD_BUS_PROPERTY("Descriptors", "ao", get_children, 0, 0),

	SD_BUS_VTABLE_END
};


static struct sd_bus_vtable vdescriptor[] = {
	SD_BUS_VTABLE_START(0),

	SD_BUS_METHOD("ReadValue", "a{sv}", "ay", read_value, 0),
	SD_BUS_METHOD("WriteValue", "aya{sv}", "", not_permitted, 0),

	SD_BUS_PROPERTY("UUID", "s", get_uuid, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Characteristic", "o", get_parent, 0, SD_BUS_VTABLE_PROPERTY_CONST),
	SD_BUS_PROPERTY("Value", "ay", get_value, 0, 0),
	SD_BUS_PROPERTY("Flags", "as", get_desc_flags, 0, 0),

	SD_BUS_VTABLE_END
};


/******** Integration ***************/

aia_uds_on_change aia_uds_set_on_change(aia_uds_on_change callback)
{
	aia_uds_on_change prev = on_change_callback;
	on_change_callback = callback;
	return prev;
}

int aia_uds_init(struct sd_bus *bus)
{
	int rc;

	if (busini)
		return 0;

	rc = sd_bus_add_object_manager(bus, NULL, ROOT);

	rc = sd_bus_add_object_vtable(bus, NULL, services[0].path,
				ITF_SERVICE, vservice, &services[0]);

	rc = sd_bus_add_object_vtable(bus, NULL, characteristics[0].path,
				ITF_CHARACTERISTIC, vcharacteristic, &characteristics[0]);
	rc = sd_bus_add_object_vtable(bus, NULL, characteristics[1].path,
				ITF_CHARACTERISTIC, vcharacteristic, &characteristics[1]);
	rc = sd_bus_add_object_vtable(bus, NULL, characteristics[2].path,
				ITF_CHARACTERISTIC, vcharacteristic, &characteristics[2]);
	rc = sd_bus_add_object_vtable(bus, NULL, characteristics[3].path,
				ITF_CHARACTERISTIC, vcharacteristic, &characteristics[3]);

	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[0].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[0]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[1].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[1]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[2].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[2]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[3].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[3]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[4].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[4]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[5].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[5]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[6].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[6]);
	rc = sd_bus_add_object_vtable(bus, NULL, descriptors[7].path,
				ITF_DESCRIPTOR, vdescriptor, &descriptors[7]);

	busini = sd_bus_ref(bus);
	return 0;
}

struct cb {
	void *callback;
	void *closure;
	int onoff;
};

static struct cb *alloccb(void *callback, void *closure, int onoff)
{
	struct cb *cb = malloc(sizeof *cb);
	if (cb) {
		cb->callback = callback;
		cb->closure = closure;
	}
	return cb;
}

static int register_uds_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	struct cb *cb = userdata;
	void (*callback)(void *closure, int error, int state);
	int iserr;

	iserr = sd_bus_message_is_method_error(m, NULL);
	if (!iserr)
		activation = cb->onoff;
	callback = cb->callback;
	if (callback)
		callback(cb->closure, iserr, activation);
	free(cb);

	return 1;
}

static int register_uds(int onoff, void *data)
{
	int rc;
	sd_bus_message *m;

	rc = sd_bus_message_new_method_call(busini, &m, "org.bluez",
			"/org/bluez/hci0", "org.bluez.GattManager1",
			onoff ? "RegisterApplication" : "UnregisterApplication" );
	rc = sd_bus_message_append_basic(m, 'o', ROOT);
	if (onoff) {
		rc = sd_bus_message_open_container(m, 'a', "{sv}");
		rc = sd_bus_message_close_container(m);
	}
	rc = sd_bus_call_async(busini, NULL, m, register_uds_cb, data, 5*1000*1000);
	sd_bus_message_unref(m);
	return rc;
}

int aia_uds_activate(int onoff, void (*callback)(void *closure, int error, int state), void *closure)
{
	int rc;
	struct cb *cb;

	if (!busini)
		return -EINVAL;

	onoff = !!onoff;
	if (activation == onoff)
		return 0;

	cb = alloccb(callback, closure, onoff);
	if (!cb)
		return -ENOMEM;

	rc = register_uds(onoff, cb);
	if (rc < 0)
		free(cb);

	return rc < 0 ? rc : 1;
}

int aia_uds_advise(int onoff, void (*callback)(void *closure, int error, int state), void *closure)
{
	return aia_uds_activate(onoff, callback, closure);
}

