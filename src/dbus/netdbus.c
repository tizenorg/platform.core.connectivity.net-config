/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "netdbus.h"
#include "netconfig.h"

#define NETCONFIG_DBUS_REPLY_TIMEOUT (10 * 1000)

#define DBUS_PARAM_TYPE_STRING		"string"
#define DBUS_PARAM_TYPE_INT16		"int16"
#define DBUS_PARAM_TYPE_UINT16		"uint16"
#define DBUS_PARAM_TYPE_INT32		"int32"
#define DBUS_PARAM_TYPE_UINT32		"uint32"
#define DBUS_PARAM_TYPE_INT64		"int64"
#define DBUS_PARAM_TYPE_UINT64		"uint64"
#define DBUS_PARAM_TYPE_DOUBLE		"double"
#define DBUS_PARAM_TYPE_BYTE		"byte"
#define DBUS_PARAM_TYPE_BOOLEAN		"boolean"
#define DBUS_PARAM_TYPE_OBJECT_PATH	"objpath"
#define DBUS_PARAM_TYPE_VARIANT		"variant"


static int __netconfig_dbus_append_param(DBusMessage *message, char *param_array[])
{
	int count = 0;
	dbus_uint32_t uint32 = 0;
	DBusMessageIter iter;
	DBusMessageIter container_iter;
	char *args = NULL;
	char *ch = NULL;

	if (param_array == NULL)
		return TRUE;

	dbus_message_iter_init_append(message, &iter);

	while (param_array[count] != NULL) {
		args = param_array[count];
		DBG("parameter %d - [%s]", count, param_array[count]);

		ch = strchr(args, ':');
		if (ch == NULL) {
			ERR("Error!!! Invalid parameter[\"%s\"]\n", args);
			return FALSE;
		}
		*ch = 0; ch++;

		if (strcmp(args, DBUS_PARAM_TYPE_STRING) == 0) {
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ch);
		} else if (strcmp(args, DBUS_PARAM_TYPE_UINT32) == 0) {
			uint32 = strtoul(ch, NULL, 0);
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &uint32);
		} else if (strcmp(args, DBUS_PARAM_TYPE_VARIANT) == 0) {
			args = ch;
			ch = strchr(args, ':');
			if (ch == NULL) {
				ERR("Error!!! Invalid data format[\"%s\"]\n", args);
				return FALSE;
			}
			*ch = 0; ch++;

			if (strcmp(args, DBUS_PARAM_TYPE_STRING) == 0) {
				dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						DBUS_TYPE_STRING_AS_STRING, &container_iter);
				dbus_message_iter_append_basic(&container_iter, DBUS_TYPE_STRING, &ch);
				dbus_message_iter_close_container(&iter, &container_iter);
			} else {
				ERR("Error!!! Not supported data format[\"%s\"]\n", args);
				return FALSE;
			}
		} else {
			ERR("Error!!! Not supported data format[\"%s\"]\n", args);
			return FALSE;
		}

		count++;
	}

	return TRUE;
}

char *netconfig_dbus_get_string(DBusMessage * msg)
{
	DBusMessageIter args;
	char *sigvalue = NULL;

	/** read these parameters */
	if (!dbus_message_iter_init(msg, &args))
		DBG("Message does not have parameters");
	else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
		DBG("Argument is not string");
	else
		dbus_message_iter_get_basic(&args, &sigvalue);

	return sigvalue;
}

DBusMessage *netconfig_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, char *param_array[])
{
	DBusError error;
	DBusConnection *conn = NULL;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;

	DBG("[DBUS Sync] %s %s %s", interface_name, method, path);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Failed to get system bus");
		return NULL;
	}

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		ERR("Error!!! Failed to GetProperties");
		dbus_connection_unref(conn);
		return NULL;
	}

	if (__netconfig_dbus_append_param(message, param_array) == FALSE) {
		ERR("Error!!! __netconfig_dbus_append_param() failed\n");
		dbus_message_unref(message);
		dbus_connection_unref(conn);
		return NULL;
	}

	dbus_error_init(&error);

	reply =	dbus_connection_send_with_reply_and_block(conn, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			ERR("Error!!! dbus_connection_send_with_reply_and_block() failed. DBus error [%s: %s]",
					error.name, error.message);

			dbus_error_free(&error);
		} else
			ERR("Error!!! Failed to get properties");

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		return NULL;
	}

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	return reply;
}

char *netconfig_wifi_get_connected_service_name(DBusMessage *message)
{
	int is_connected = 0;
	char *essid_name = NULL;
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, string;
		const char *key = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "State") == TRUE && is_connected == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &string);

			if (dbus_message_iter_get_arg_type(&string) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&string, &key);

				if (g_str_equal(key, "ready") == TRUE || g_str_equal(key, "online") == TRUE)
					is_connected = 1;
			}
		} else if (g_str_equal(key, "Name") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &string);

			if (dbus_message_iter_get_arg_type(&string) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&string, &key);

				essid_name = (char *)g_strdup(key);
			}
		}

		dbus_message_iter_next(&array);
	}

	if (is_connected == 1 && essid_name != NULL)
		return essid_name;

	if (essid_name != NULL)
		g_free(essid_name);

	return NULL;
}

void netconfig_dbus_parse_recursive(DBusMessageIter *iter,
		netconfig_dbus_result_type result_type, void *data)
{
	unsigned char *bgscan_mode = NULL;
	static dbus_bool_t default_tech_flag = FALSE;
	char *default_tech = NULL;

	if (result_type == NETCONFIG_DBUS_RESULT_GET_BGSCAN_MODE)
		bgscan_mode = (unsigned char *)data;
	else if (result_type == NETCONFIG_DBUS_RESULT_DEFAULT_TECHNOLOGY)
		default_tech = (char *)data;

	do {
		int ArgType = dbus_message_iter_get_arg_type(iter);

		if (ArgType == DBUS_TYPE_INVALID)
			break;

		switch (ArgType) {
		case DBUS_TYPE_BYTE:
		{
			unsigned char Value = 0;

			dbus_message_iter_get_basic(iter, &Value);

			*bgscan_mode = Value;
			INFO("BG scan mode: %d, %d", *bgscan_mode, Value);
			break;
		}

		case DBUS_TYPE_STRING:
		{
			char *Value = NULL;

			dbus_message_iter_get_basic(iter, &Value);

			INFO("result type: %d, string: %s", result_type, Value);
			if (result_type == NETCONFIG_DBUS_RESULT_DEFAULT_TECHNOLOGY) {
				if (strcmp(Value, "DefaultTechnology") == 0) {
					default_tech_flag = TRUE;
				} else {
					if (default_tech_flag == TRUE) {
						sprintf(default_tech, "%s", Value);
						INFO("default technology: %s", default_tech);
						default_tech_flag =	FALSE;
					}
				}
			}
			break;
		}

		case DBUS_TYPE_SIGNATURE:
		{
			char *Value = NULL;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_OBJECT_PATH:
		{
			char *Value = NULL;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_INT16:
		{
			dbus_int16_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_UINT16:
		{
			dbus_uint16_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_INT32:
		{
			dbus_int32_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_UINT32:
		{
			dbus_uint32_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_INT64:
		{
			dbus_int64_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_UINT64:
		{
			dbus_uint64_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_DOUBLE:
		{
			double Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_BOOLEAN:
		{
			dbus_bool_t Value = 0;

			dbus_message_iter_get_basic(iter, &Value);
			break;
		}

		case DBUS_TYPE_VARIANT:
		{
			DBusMessageIter SubIter;

			dbus_message_iter_recurse(iter, &SubIter);
			netconfig_dbus_parse_recursive(&SubIter,
					result_type, data);
			break;
		}

		case DBUS_TYPE_ARRAY:
		{
			int CurrentType = 0;
			DBusMessageIter SubIter;

			dbus_message_iter_recurse(iter, &SubIter);
			CurrentType = dbus_message_iter_get_arg_type(&SubIter);

			while (CurrentType != DBUS_TYPE_INVALID) {
				netconfig_dbus_parse_recursive(&SubIter,
						result_type, data);

				dbus_message_iter_next(&SubIter);
				CurrentType = dbus_message_iter_get_arg_type(&SubIter);
			}
			break;
		}

		case DBUS_TYPE_DICT_ENTRY:
		{
			DBusMessageIter SubIter;

			dbus_message_iter_recurse(iter, &SubIter);
			netconfig_dbus_parse_recursive(&SubIter, result_type, data);

			dbus_message_iter_next(&SubIter);
			netconfig_dbus_parse_recursive(&SubIter, result_type, data);
			break;
		}

		case DBUS_TYPE_STRUCT:
		{
			int CurrentType = 0;
			DBusMessageIter SubIter;

			dbus_message_iter_recurse(iter, &SubIter);

			while ((CurrentType = dbus_message_iter_get_arg_type(&SubIter))
					!= DBUS_TYPE_INVALID) {
				netconfig_dbus_parse_recursive(&SubIter, result_type, data);

				dbus_message_iter_next(&SubIter);
			}
			break;
		}

		default:
			ERR("Error!!! Invalid Argument Type [%c]", ArgType);
		}
	} while (dbus_message_iter_next(iter));
}

DBusGConnection *netconfig_setup_dbus(void)
{
	DBusGConnection* connection = NULL;
	GError *error = NULL;
	DBusGProxy *proxy;
	guint rv = 0;

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Fail to get DBus(%s)", error->message);
		return connection;
	}

	INFO("Successfully get system DBus connection(%p)", connection);

	proxy = dbus_g_proxy_new_for_name(connection, "org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus");

	if (!dbus_g_proxy_call(proxy, "RequestName", &error,
			G_TYPE_STRING, NETCONFIG_SERVICE, G_TYPE_UINT, 0,
			G_TYPE_INVALID, G_TYPE_UINT, &rv,
			G_TYPE_INVALID)) {
		ERR("Failed to acquire service(%s) error(%s)",
				NETCONFIG_SERVICE, error->message);

		dbus_g_connection_unref(connection);

		return NULL;
	}

	if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		ERR("Service name is already in use");

		dbus_g_connection_unref(connection);

		return NULL;
	}

	return connection;
}
