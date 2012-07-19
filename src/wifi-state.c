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

#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "dbus.h"
#include "util.h"
#include "wifi-state.h"
#include "wifi-background-scan.h"

static enum netconfig_wifi_service_state
	wifi_service_state = NETCONFIG_WIFI_UNKNOWN;

void netconfig_wifi_state_set_service_state(
		enum netconfig_wifi_service_state state)
{
	if (wifi_service_state != state)
		wifi_service_state = state;
}

static GSList *__netconfig_wifi_state_get_service_profiles(DBusMessage *message)
{
	GSList *service_profiles = NULL;
	DBusMessageIter iter, dict;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter keyValue, array, value;
		const char *key = NULL;
		const char *object_path = NULL;

		dbus_message_iter_recurse(&dict, &keyValue);
		dbus_message_iter_get_basic(&keyValue, &key);

		if (g_str_equal(key, "Services") != TRUE) {
			dbus_message_iter_next(&dict);
			continue;
		}

		dbus_message_iter_next(&keyValue);
		dbus_message_iter_recurse(&keyValue, &array);
		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
			return service_profiles;

		dbus_message_iter_recurse(&array, &value);
		if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_OBJECT_PATH)
			return service_profiles;

		while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
			dbus_message_iter_get_basic(&value, &object_path);

			if (g_str_has_prefix(object_path, "/profile/default/wifi_") ==TRUE)
				service_profiles = g_slist_append(service_profiles, g_strdup(object_path));

			dbus_message_iter_next(&value);
		}

		dbus_message_iter_next(&dict);
	}

	return service_profiles;
}

static enum netconfig_wifi_service_state
__netconfig_wifi_state_get_state_from_service(DBusMessage *message)
{
	enum netconfig_wifi_service_state wifi_state = NETCONFIG_WIFI_UNKNOWN;
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, dict;
		const char *key = NULL;
		const char *temp = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "Type") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &dict);
			dbus_message_iter_get_basic(&dict, &temp);

			if (g_str_equal(temp, "wifi") == TRUE)
				break;
			else
				return wifi_state;
		}

		dbus_message_iter_next(&array);
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key = NULL;
		const char *value = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &variant);

		if (g_str_equal(key, "State") != TRUE) {
			dbus_message_iter_next(&array);
			continue;
		}

		dbus_message_iter_get_basic(&variant, &value);

		if (g_str_equal(value, "idle") == TRUE)
			wifi_state = NETCONFIG_WIFI_IDLE;
		else if (g_str_equal(value, "failure") == TRUE)
			wifi_state = NETCONFIG_WIFI_IDLE;
		else if (g_str_equal(value, "association") == TRUE)
			wifi_state = NETCONFIG_WIFI_CONNECTING;
		else if (g_str_equal(value, "configuration") == TRUE)
			wifi_state = NETCONFIG_WIFI_CONNECTING;
		else if (g_str_equal(value, "ready") == TRUE)
			wifi_state = NETCONFIG_WIFI_CONNECTED;
		else if (g_str_equal(value, "disconnect") == TRUE)
			wifi_state = NETCONFIG_WIFI_IDLE;
		else if (g_str_equal(value, "online") == TRUE)
			wifi_state = NETCONFIG_WIFI_CONNECTED;
		else
			wifi_state = NETCONFIG_WIFI_UNKNOWN;

		break;
	}

	return wifi_state;
}

static enum netconfig_wifi_service_state
__netconfig_wifi_state_get_connman_service_state(void)
{
	enum netconfig_wifi_service_state wifi_state = NETCONFIG_WIFI_UNKNOWN;
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	GSList *service_profiles = NULL;
	GSList *list = NULL;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");

		return wifi_state;
	}

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, connection,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE, "GetProperties");
	if (message == NULL) {
		ERR("Failed to get service list");
		dbus_connection_unref(connection);

		return wifi_state;
	}

	/* Get service profiles from ConnMan Manager */
	service_profiles = __netconfig_wifi_state_get_service_profiles(message);
	dbus_message_unref(message);

	for (list = service_profiles; list != NULL; list = list->next) {
		char *profile_path = list->data;
		enum netconfig_wifi_service_state wifi_service_state = wifi_state;

		message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, connection,
				profile_path, CONNMAN_SERVICE_INTERFACE, "GetProperties");

		if (message == NULL) {
			ERR("Failed to get service information of %s", profile_path);
			continue;
		}

		/* Get service information from ConnMan Service */
		wifi_service_state = __netconfig_wifi_state_get_state_from_service(message);
		if (wifi_state < wifi_service_state)
			wifi_state = wifi_service_state;

		dbus_message_unref(message);
	}

	g_slist_free(service_profiles);
	dbus_connection_unref(connection);

	return wifi_state;
}

enum netconfig_wifi_service_state
netconfig_wifi_state_get_service_state(void)
{
	if (wifi_service_state == NETCONFIG_WIFI_CONNECTED)
		return NETCONFIG_WIFI_CONNECTED;

	return __netconfig_wifi_state_get_connman_service_state();
}

gchar *netconfig_wifi_get_technology_state(void)
{
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter args, dict;
	gboolean wifi_tech_available = FALSE;
	gboolean wifi_tech_enabled = FALSE;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return NULL;
	}

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, connection,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE, "GetProperties");
	if (message == NULL) {
		ERR("Failed to get Wi-Fi technology state");
		dbus_connection_unref(connection);
		return NULL;
	}

	dbus_message_iter_init(message, &args);
	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter key_iter, sub_iter1, sub_iter2;
		const char *key = NULL;
		const char *tech_name = NULL;

		dbus_message_iter_recurse(&dict, &key_iter);
		dbus_message_iter_get_basic(&key_iter, &key);

		if (strcmp(key, "AvailableTechnologies") == 0 ||
				strcmp(key, "EnabledTechnologies") == 0) {
			dbus_message_iter_next(&key_iter);
			dbus_message_iter_recurse(&key_iter, &sub_iter1);

			if (dbus_message_iter_get_arg_type(&sub_iter1) == DBUS_TYPE_ARRAY)
				dbus_message_iter_recurse(&sub_iter1, &sub_iter2);
			else
				goto next_dict;

			while (dbus_message_iter_get_arg_type(&sub_iter2) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_iter2, &tech_name);

				if (tech_name != NULL && strcmp(tech_name, "wifi") == 0) {
					if (strcmp(key, "AvailableTechnologies") == 0)
						wifi_tech_available = TRUE;
					else if (strcmp(key, "EnabledTechnologies") == 0)
						wifi_tech_enabled = TRUE;
				}

				dbus_message_iter_next(&sub_iter2);
			}
		}

next_dict:
		dbus_message_iter_next(&dict);
	}

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	if (wifi_tech_enabled)
		return g_strdup("EnabledTechnologies");
	else if (wifi_tech_available)
		return g_strdup("AvailableTechnologies");
	else
		return NULL;
}

void netconfig_wifi_update_power_state(gboolean powered)
{
	int wifi_state = 0;

	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

	if (powered == TRUE) {
		if (wifi_state == VCONFKEY_WIFI_OFF &&
				netconfig_is_wifi_direct_on() != TRUE &&
				netconfig_is_wifi_tethering_on() != TRUE) {
			DBG("Wi-Fi successfully turned on");

			vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

			vconf_set_int(VCONF_WIFI_LAST_POWER_ON_STATE, WIFI_POWER_ON);

			vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);

			netconfig_wifi_bgscan_start();
		}
	} else {
		netconfig_wifi_bgscan_stop();

		if (wifi_state != VCONFKEY_WIFI_OFF) {
			DBG("Wi-Fi successfully turned off");

			vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_OFF);

			vconf_set_int(VCONF_WIFI_LAST_POWER_ON_STATE, WIFI_POWER_OFF);

			vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_OFF);
		}
	}
}
