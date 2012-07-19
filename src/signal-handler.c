/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Danny JS Seo <S.Seo@samsung.com>
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
#include <dbus/dbus-glib-lowlevel.h>

#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "dbus.h"
#include "util.h"
#include "wifi-state.h"
#include "wifi-indicator.h"
#include "wifi-background-scan.h"
#include "neterror.h"

#define CONNMAN_SIGNAL_PROPERTY_CHANGED		"PropertyChanged"

#define CONNMAN_MANAGER_SIGNAL_FILTER		"type='signal',interface='net.connman.Manager'"
#define CONNMAN_TECHNOLOGY_SIGNAL_FILTER	"type='signal',interface='net.connman.Technology'"
#define CONNMAN_SERVICE_SIGNAL_FILTER		"type='signal',interface='net.connman.Service'"

static DBusConnection *signal_connection = NULL;

static int __netconfig_get_state(DBusMessage *msg, char *state)
{
	char *key_name = NULL;
	char *svc_state = NULL;
	DBusMessageIter iter, sub_iter;
	int Error = NETCONFIG_ERROR_INTERNAL;

	/* Get state */
	dbus_message_iter_init(msg, &iter);
	int ArgType = dbus_message_iter_get_arg_type(&iter);

	if (ArgType != DBUS_TYPE_STRING)
		goto done;

	dbus_message_iter_get_basic(&iter, &key_name);
	if (g_str_equal(key_name, "State") != TRUE)
		goto done;

	dbus_message_iter_next(&iter);
	ArgType = dbus_message_iter_get_arg_type(&iter);
	if (ArgType != DBUS_TYPE_VARIANT)
		goto done;

	dbus_message_iter_recurse(&iter, &sub_iter);
	ArgType = dbus_message_iter_get_arg_type(&sub_iter);
	if (ArgType != DBUS_TYPE_STRING)
		goto done;

	dbus_message_iter_get_basic(&sub_iter, &svc_state);
	snprintf(state, strlen(svc_state) + 1, "%s", svc_state);
	Error = NETCONFIG_NO_ERROR;

done:
	return Error;
}

static char *__netconfig_get_property(DBusMessage * msg, char **property)
{
	DBusMessageIter args, variant;
	char *sigvalue = NULL;

	/** read these parameters */
	if (!dbus_message_iter_init(msg, &args))
		ERR("Message does not have parameters");
	else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		ERR("Argument is not string");
	else {
		dbus_message_iter_get_basic(&args, &sigvalue);
		dbus_message_iter_next(&args);
		dbus_message_iter_recurse(&args, &variant);
		if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING)
			dbus_message_iter_get_basic(&variant, property);
		else
			*property = NULL;
	}

	return sigvalue;
}

static void __netconfig_wifi_technology_state_signal_handler(
		const char *sigvalue, const char *property)
{
	static char previous_technology_state[DBUS_STATE_MAX_BUFLEN] = {0};

	if (sigvalue == NULL || property == NULL)
		return;

	if (g_str_equal(sigvalue, "State") != TRUE)
		return;

	if (g_str_equal(property, "unknown") == TRUE)
		return;

	if (g_str_equal(previous_technology_state, property) == TRUE)
		return;

	g_strlcpy(previous_technology_state, property, sizeof(previous_technology_state));

	INFO("Technology state value is %s, property %s", sigvalue, property);

	if (g_str_equal(property, "offline") == TRUE) {
		gchar *wifi_tech_state = NULL;

		wifi_tech_state = netconfig_wifi_get_technology_state();
		INFO("Wi-Fi technology state: %s", wifi_tech_state);

		if (wifi_tech_state == NULL)
			netconfig_wifi_update_power_state(FALSE);
		else {
			if (g_str_equal(wifi_tech_state, "EnabledTechnologies") != TRUE)
				netconfig_wifi_update_power_state(FALSE);

			g_free(wifi_tech_state);
		}
	} else if (g_str_equal(property, "enabled") == TRUE)
		netconfig_wifi_update_power_state(TRUE);
}

static void netconfig_wifi_set_essid(const char *active_profile)
{
	int err;
	char *essid_name = NULL;
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	int MessageType = 0;

	if (active_profile == NULL) {
		ERR("Can't get active_profile");
		return;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return;
	}

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, connection, active_profile,
			CONNMAN_SERVICE_INTERFACE, "GetProperties");

	if (message == NULL) {
		ERR("Failed to get service properties");
		dbus_connection_unref(connection);
		return;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", ptr);
		goto done;
	}

	essid_name = netconfig_wifi_get_connected_service_name(message);

	if (essid_name == NULL) {
		ERR("Wi-Fi is not connected");
		goto done;
	}

	err = vconf_set_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, essid_name);
	if (err != 0) {
		ERR("Can't set essid [%d]", err);
	}

	g_free(essid_name);
	essid_name = NULL;

done:
	dbus_message_unref(message);

	dbus_connection_unref(connection);
}

static void netconfig_wifi_unset_essid(void)
{
	vconf_set_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, "");
}

static void __netconfig_wifi_service_state_signal_handler(DBusMessage *msg, const char *profile)
{
	char state[DBUS_STATE_MAX_BUFLEN] = {0};
	static char current_profile[DBUS_PATH_MAX_BUFLEN] = {0};

	if (profile == NULL)
		return;

	if (__netconfig_get_state(msg, state) == NETCONFIG_NO_ERROR) {
		int wifi_state = 0;

		DBG("Signaled profile [%s] ==> state %s", profile, state);

		vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
		DBG("Current Wi-Fi state: %d", wifi_state);

		if (g_str_equal(state, "ready") == TRUE || g_str_equal(state, "online") == TRUE) {
			if (wifi_state > VCONFKEY_WIFI_OFF && wifi_state != VCONFKEY_WIFI_CONNECTED) {

				INFO("Wifi connected");

				if ((vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_CONNECTED)) < 0)
					ERR("Error!!! vconf_set_int failed");

				netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTED);

				netconfig_wifi_set_essid(profile);

				netconfig_wifi_indicator_start();

				g_strlcpy(current_profile, profile, sizeof(current_profile));
			}
		} else if (g_str_equal(state, "failure") == TRUE || g_str_equal(state, "disconnect") == TRUE || g_str_equal(state, "idle") == TRUE) {
			if (wifi_state > VCONFKEY_WIFI_UNCONNECTED) {

				INFO("Wifi [%s] Disconnected", profile);
				DBG("Current profile is %s", current_profile);

				if ((g_str_equal(profile, current_profile)) == TRUE)
					if ((vconf_set_int (VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED)) < 0)
						ERR("Error!!! vconf_set_int failed");
			}

			netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_IDLE);

			netconfig_wifi_unset_essid();

			netconfig_wifi_indicator_stop();

			memset(current_profile, 0, sizeof(current_profile));
		} else if (g_str_equal(state, "association") == TRUE || g_str_equal(state, "configuration") == TRUE) {
			netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTING);
		}
	} else
		DBG("Signaled profile [%s] has error to get its state", profile);
}

static DBusHandlerResult __netconfig_signal_filter_handler(
		DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	char *sigvalue = NULL;

	if (msg == NULL) {
		INFO("Invalid Message. Ignore");

		/* We have handled this message, don't pass it on */
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		/* We have handled this message, don't pass it on */
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_TECHNOLOGY_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		char *property = NULL;
		char *technology_path = NULL;

		sigvalue = __netconfig_get_property(msg, &property);
		if (sigvalue == NULL)
			return DBUS_HANDLER_RESULT_HANDLED;

		technology_path = (char *)dbus_message_get_path(msg);
		INFO("technology object path: %s", technology_path);

		if (g_str_has_prefix(technology_path, CONNMAN_WIFI_TECHNOLOGY_PREFIX) == TRUE) {
			__netconfig_wifi_technology_state_signal_handler((const char *)sigvalue, (const char *)property);
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		/* We have handled this message, don't pass it on */
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_SERVICE_INTERFACE, CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		sigvalue = netconfig_dbus_get_string(msg);

		if (sigvalue == NULL)
			return DBUS_HANDLER_RESULT_HANDLED;

		if (g_str_equal(sigvalue, "State") == TRUE) {
			char *service_profile = NULL;

			service_profile = (char *)dbus_message_get_path(msg);
			INFO("service profile: %s", service_profile);

			if (g_str_has_prefix(service_profile, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE) {
				__netconfig_wifi_service_state_signal_handler(msg, service_profile);
				return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			}
		}
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

void netconfig_register_signal(void)
{
	DBusConnection *conn = NULL;
	DBusError err;

	DBG("Register DBus signal filters");

	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Error! Failed to connect to the D-BUS daemon: [%s]",
				err.message);
		dbus_error_free(&err);
		return;
	}

	signal_connection = conn;

	dbus_connection_setup_with_g_main(conn, NULL);

	/* listening to messages from all objects as no path is specified */
	/* see signals from the given interface */
	dbus_bus_add_match(conn, CONNMAN_MANAGER_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_TECHNOLOGY_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	if (dbus_connection_add_filter(conn, __netconfig_signal_filter_handler, NULL, NULL)
			== FALSE) {
		ERR("Error! dbus_connection_add_filter() failed");
		return;
	}

	INFO("Successfully register signal filters");
}

void netconfig_deregister_signal(void)
{
	if (signal_connection == NULL) {
		ERR("Error! Already de-registered. Nothing to be done");
		return;
	}

	dbus_connection_remove_filter(signal_connection, __netconfig_signal_filter_handler,
			NULL);
	INFO("Successfully remove DBus signal filters");

	dbus_connection_unref(signal_connection);
	signal_connection = NULL;
}
