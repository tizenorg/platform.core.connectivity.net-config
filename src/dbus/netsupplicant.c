/*
 * Network Configuration Module
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "log.h"
#include "netdbus.h"
#include "netsupplicant.h"

#define DBUS_OBJECT_PATH_MAX			150
#define NETCONFIG_DBUS_REPLY_TIMEOUT	(10 * 1000)

static void setup_dbus_args(gpointer data, gpointer user_data)
{
	DBusMessageIter *iter;
	struct dbus_input_arguments *args;

	if (data == NULL || user_data == NULL)
		return;

	iter = (DBusMessageIter *) user_data;
	args = (struct dbus_input_arguments *)data;

	if (args->data == NULL)
		return;

	switch (args->type) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		DBG("parameter [%s]", args->data);
		dbus_message_iter_append_basic(iter, args->type, &(args->data));
		break;
	case DBUS_TYPE_BOOLEAN:
	case DBUS_TYPE_UINT32:
	case DBUS_TYPE_INT32:
		DBG("parameter [%d]", args->data);
		dbus_message_iter_append_basic(iter, args->type, args->data);
		break;
	case DBUS_TYPE_INVALID:
	default:
		return;
	}
}

GList *setup_input_args(GList *list,
		struct dbus_input_arguments *items)
{
	struct dbus_input_arguments *iter = items;

	if (iter == NULL)
		return NULL;

	while (iter->data) {
		list = g_list_append(list, iter); //Adds a new element on to the end of the list
		iter++;
	}

	return list;
}

gboolean netconfig_wifi_get_ifname(char **ifname)
{
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int MessageType = 0;
	char *ptr = (char *)*ifname;
	const char *temp = NULL;

	char object_path[DBUS_PATH_MAX_BUFLEN] = { 0, };
	char *path_ptr = &object_path[0];

	GList *input_args = NULL;
	struct dbus_input_arguments args[] = {
			{DBUS_TYPE_STRING, SUPPLICANT_INTERFACE ".Interface"},
			{DBUS_TYPE_STRING, "Ifname"},
			{0, NULL}
	};

	if (ptr == NULL)
		return FALSE;

	if (netconfig_wifi_get_supplicant_interface(&path_ptr) != TRUE) {
		DBG("Fail to get wpa_supplicant DBus path");
		return FALSE;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Error!!! Fail to get system DBus");
		return FALSE;
	}

	input_args = setup_input_args(input_args, args);

	message = netconfig_supplicant_invoke_dbus_method(
			SUPPLICANT_SERVICE, connection,
			path_ptr,
			SUPPLICANT_GLOBAL_INTERFACE, "Get",
			input_args);

	g_list_free(input_args);

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto error;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received %s", err_ptr);
		goto error;
	}

	dbus_message_iter_init(message, &iter);

	if ((MessageType = dbus_message_iter_get_arg_type(&iter))
			== DBUS_TYPE_VARIANT) {
		DBusMessageIter string_type;
		dbus_message_iter_recurse(&iter, &string_type);

		if ((MessageType = dbus_message_iter_get_arg_type(&string_type))
				== DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&string_type, &temp);
		} else
			goto error;
	} else
		goto error;

	g_strlcpy(ptr, temp, 16);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return TRUE;

error:
	if (message != NULL)
		dbus_message_unref(message);

	if (connection != NULL)
		dbus_connection_unref(connection);

	return FALSE;
}

gboolean netconfig_wifi_get_supplicant_interface(char **path)
{
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int MessageType = 0;
	char *ptr = (char *)*path;
	const char *temp = NULL;

	GList *input_args = NULL;
	struct dbus_input_arguments args[] = {
			{DBUS_TYPE_STRING, SUPPLICANT_INTERFACE},
			{DBUS_TYPE_STRING, "Interfaces"},
			{0, NULL}
	};

	if (ptr == NULL)
		return FALSE;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Error!!! Fail to get system DBus");
		return FALSE;
	}

	input_args = setup_input_args(input_args, args);

	message = netconfig_supplicant_invoke_dbus_method(
			SUPPLICANT_SERVICE, connection,
			SUPPLICANT_PATH,
			SUPPLICANT_GLOBAL_INTERFACE, "Get",
			input_args);

	g_list_free(input_args);

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto error;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received %s", err_msg);
		goto error;
	}

	dbus_message_iter_init(message, &iter);
	if ((MessageType = dbus_message_iter_get_arg_type(&iter))
			== DBUS_TYPE_VARIANT) {
		DBusMessageIter array;
		dbus_message_iter_recurse(&iter, &array);

		if ((MessageType = dbus_message_iter_get_arg_type(&array))
				== DBUS_TYPE_ARRAY) {
			DBusMessageIter object_path;
			dbus_message_iter_recurse(&array, &object_path);

			if ((MessageType = dbus_message_iter_get_arg_type(&object_path))
					== DBUS_TYPE_OBJECT_PATH)
				dbus_message_iter_get_basic(&object_path, &temp);
			else
				goto error;
		} else
			goto error;
	} else
		goto error;

	g_strlcpy(ptr, temp, DBUS_PATH_MAX_BUFLEN);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return TRUE;

error:
	if (message != NULL)
		dbus_message_unref(message);

	if (connection != NULL)
		dbus_connection_unref(connection);

	return FALSE;
}

const char *netconfig_wifi_get_supplicant_interface_(void)
{
	GList *input_args = NULL;
	DBusMessage *message = NULL;
	struct dbus_input_arguments args[] = {
			{DBUS_TYPE_STRING, WIFI_IFNAME},
			{DBUS_TYPE_INVALID, NULL}
	};
	const char *path;
	static char obj_path[DBUS_OBJECT_PATH_MAX] = { '\0', };

	if (obj_path[0] != '\0')
		return (const char *)obj_path;

	input_args = setup_input_args(input_args, args);

	message = netconfig_supplicant_invoke_dbus_method_(
			SUPPLICANT_SERVICE, SUPPLICANT_PATH,
			SUPPLICANT_INTERFACE, "GetInterface", input_args);

	g_list_free(input_args);

	if (message == NULL)
		return NULL;

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received %s", err_msg);
		goto error;
	}

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	g_strlcpy(obj_path, path, DBUS_OBJECT_PATH_MAX);

	dbus_message_unref(message);

	return (const char *)obj_path;

error:
	if (message != NULL)
		dbus_message_unref(message);

	return NULL;
}


DBusMessage *netconfig_supplicant_invoke_dbus_method(const char *dest,
		DBusConnection *connection,
		const char *path, const char *interface_name,
		const char *method, GList *args)
{
	DBusError error;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		ERR("Error!!! DBus method call fail");
		return NULL;
	}

	dbus_message_iter_init_append(message, &iter);

	if (args != NULL)
		g_list_foreach(args, setup_dbus_args, (gpointer) &iter);

	dbus_error_init(&error);

	reply =	dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			ERR("Error!!! dbus_connection_send_with_reply_and_block() failed. DBus error [%s: %s]",
					error.name, error.message);

			dbus_error_free(&error);
		} else
			ERR("Error!!! Failed to get properties");

		dbus_message_unref(message);

		return NULL;
	}

	dbus_message_unref(message);

	return reply;
}

DBusMessage *netconfig_supplicant_invoke_dbus_method_(const char *dest,
		const char *path, const char *interface_name,
		const char *method, GList *args)
{
	DBusError error;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;

//	DBG("[DBUS Sync] %s %s %s", interface_name, method, path);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return NULL;
	}

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return NULL;
	}

	dbus_message_iter_init_append(message, &iter);

	if (args != NULL)
		g_list_foreach(args, setup_dbus_args, (gpointer)&iter);

	dbus_error_init(&error);

	reply =	dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			ERR("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		} else
			ERR("Failed to get properties");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return NULL;
	}

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return reply;
}

DBusMessage *netconfig_supplicant_invoke_dbus_interface_property_get(const char *interface,
			const char *key)
{
	DBusError error;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;
	const char *path;

	ERR("[DBUS] property_get : %s", key);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return NULL;
	}

	path = netconfig_wifi_get_supplicant_interface_();
	if (path == NULL) {
		DBG("Failed to get wpa_supplicant DBus path");
		dbus_connection_unref(connection);
		return NULL;
	}

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE, path,
					DBUS_INTERFACE_PROPERTIES, "Get");
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return NULL;
	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &interface,
					DBUS_TYPE_STRING, &key, NULL);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
				NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			ERR("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		} else
			ERR("Failed to get properties");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return NULL;
	}

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return reply;
}

dbus_bool_t netconfig_supplicant_invoke_dbus_interface_property_set(const char *interface,
			const char *key, const char *type, GList *args,
			DBusPendingCallNotifyFunction notify_func)
{
	dbus_bool_t result = FALSE;
	DBusPendingCall *call;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;
	DBusMessageIter iter, value;
	const char *path;

	DBG("[DBUS] property_set : %s", key);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return result;
	}

	path = netconfig_wifi_get_supplicant_interface_();
	if (path == NULL) {
		ERR("Failed to get wpa_supplicant DBus path");
		dbus_connection_unref(connection);
		return result;
	}

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE, path,
					DBUS_INTERFACE_PROPERTIES, "Set");
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return result;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					type, &value);

	if (args != NULL)
		g_list_foreach(args, setup_dbus_args, (gpointer)&value);

	dbus_message_iter_close_container(&iter, &value);

	result = dbus_connection_send_with_reply(connection, message, &call,
			NETCONFIG_DBUS_REPLY_TIMEOUT);
	if (result == FALSE || call == NULL) {
		ERR("dbus_connection_send_with_reply() failed");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return result;
	}

	if (notify_func == NULL)
		dbus_pending_call_cancel(call);
	else
		dbus_pending_call_set_notify(call, notify_func, NULL, NULL);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return result;
}

