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

#include <vconf.h>
#include <vconf-keys.h>
#include <syspopup_caller.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "network-statistics.h"
#include "wifi-state.h"
#include "wifi-background-scan.h"

static int profiles_count = 0;

static enum netconfig_wifi_service_state
	wifi_service_state = NETCONFIG_WIFI_UNKNOWN;

static GSList *notifier_list = NULL;


static gboolean __netconfig_wifi_add_network_notification(void)
{
	int rv = 0;
	bundle *b = NULL;

	b = bundle_create();
	bundle_add(b, "_SYSPOPUP_TYPE_", "wifi_notification");
	bundle_add(b, "_SYSPOPUP_CONTENT_", "add");

	DBG("Register Wi-Fi network notification");
	rv = syspopup_launch("net-popup", b);

	bundle_free(b);

	return TRUE;
}

static gboolean __netconfig_wifi_del_network_notification(void)
{
	int rv = 0;
	bundle *b = NULL;

	b = bundle_create();
	bundle_add(b, "_SYSPOPUP_TYPE_", "wifi_notification");
	bundle_add(b, "_SYSPOPUP_CONTENT_", "delete");

	DBG("Delete Wi-Fi network notification");
	rv = syspopup_launch("net-popup", b);

	bundle_free(b);

	return TRUE;
}

static void __netconfig_wifi_set_profiles_count(const int count)
{
	profiles_count = count;
}

static int __netconfig_wifi_get_profiles_count(void)
{
	return profiles_count;
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

			if (g_str_has_prefix(object_path, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE)
				service_profiles = g_slist_append(service_profiles, g_strdup(object_path));

			dbus_message_iter_next(&value);
		}

		dbus_message_iter_next(&dict);
	}

	return service_profiles;
}

static char *__netconfig_wifi_get_connman_favorite_service(void)
{
	char *favorite_service = NULL;
	DBusMessage *message = NULL;
	GSList *service_profiles = NULL;
	GSList *list = NULL;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");

		return NULL;
	}

	/* Get service profiles from ConnMan Manager */
	service_profiles = __netconfig_wifi_state_get_service_profiles(message);
	dbus_message_unref(message);

	for (list = service_profiles; list != NULL; list = list->next) {
		char *profile_path = list->data;
		DBusMessageIter iter, array;

		if (favorite_service != NULL)
			break;

		message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
				profile_path, CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);

		if (message == NULL) {
			ERR("Failed to get service information of %s", profile_path);
			continue;
		}

		dbus_message_iter_init(message, &iter);
		dbus_message_iter_recurse(&iter, &array);

		while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry, variant;
			const char *key = NULL;
			dbus_bool_t value;

			dbus_message_iter_recurse(&array, &entry);
			dbus_message_iter_get_basic(&entry, &key);

			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);

			if (g_str_equal(key, "Favorite") != TRUE) {
				dbus_message_iter_next(&array);
				continue;
			}

			dbus_message_iter_get_basic(&variant, &value);

			if (value)
				favorite_service = g_strdup(profile_path);

			break;
		}

		dbus_message_unref(message);
	}

	g_slist_free(service_profiles);

	return favorite_service;
}

static void __netconfig_wifi_state_changed(
		enum netconfig_wifi_service_state state)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct netconfig_wifi_state_notifier *notifier = list->data;

		if (notifier->netconfig_wifi_state_changed != NULL)
			notifier->netconfig_wifi_state_changed(state, notifier->user_data);
	}
}

void netconfig_wifi_state_set_service_state(
		enum netconfig_wifi_service_state state)
{
	if (wifi_service_state == state)
		return;

	wifi_service_state = state;
	DBG("Wi-Fi state %d", state);

	if (wifi_service_state == NETCONFIG_WIFI_CONNECTED)
		__netconfig_wifi_del_network_notification();

	__netconfig_wifi_state_changed(state);
}

enum netconfig_wifi_service_state
netconfig_wifi_state_get_service_state(void)
{
	return wifi_service_state;
}

gchar *netconfig_wifi_get_technology_state(void)
{
	DBusMessage *message = NULL;
	DBusMessageIter args, dict;
	gboolean wifi_tech_available = FALSE;
	gboolean wifi_tech_enabled = FALSE;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get Wi-Fi technology state");
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

		if (g_str_equal(key, "AvailableTechnologies") == TRUE ||
				g_str_equal(key, "EnabledTechnologies") == TRUE) {
			dbus_message_iter_next(&key_iter);
			dbus_message_iter_recurse(&key_iter, &sub_iter1);

			if (dbus_message_iter_get_arg_type(&sub_iter1) == DBUS_TYPE_ARRAY)
				dbus_message_iter_recurse(&sub_iter1, &sub_iter2);
			else
				goto next_dict;

			while (dbus_message_iter_get_arg_type(&sub_iter2) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_iter2, &tech_name);

				if (tech_name != NULL && g_str_equal(tech_name, "wifi") == TRUE) {
					if (g_str_equal(key, "AvailableTechnologies") == TRUE)
						wifi_tech_available = TRUE;
					else if (g_str_equal(key, "EnabledTechnologies") == TRUE)
						wifi_tech_enabled = TRUE;
				}

				dbus_message_iter_next(&sub_iter2);
			}
		}

next_dict:
		dbus_message_iter_next(&dict);
	}

	dbus_message_unref(message);

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

			vconf_set_int(VCONF_WIFI_LAST_POWER_STATE, WIFI_POWER_ON);

			vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);

			netconfig_wifi_bgscan_start();
		}
	} else {
		if (wifi_state != VCONFKEY_WIFI_OFF) {
			DBG("Wi-Fi successfully turned off");

			__netconfig_wifi_del_network_notification();

			netconfig_wifi_bgscan_stop();

			__netconfig_wifi_set_profiles_count(0);

			vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_OFF);

			vconf_set_int(VCONF_WIFI_LAST_POWER_STATE, WIFI_POWER_OFF);

			vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_OFF);
		}
	}
}

char *netconfig_wifi_get_favorite_service(void)
{
	return __netconfig_wifi_get_connman_favorite_service();
}

void netconfig_wifi_check_network_notification(void)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter, dict;
	int profiles_count = 0;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");
		return;
	}

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
			continue;

		dbus_message_iter_recurse(&array, &value);
		while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
			dbus_message_iter_get_basic(&value, &object_path);

			if (g_str_has_prefix(object_path, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE)
				profiles_count++;

			dbus_message_iter_next(&value);
		}

		dbus_message_iter_next(&dict);
	}

	dbus_message_unref(message);

	if (__netconfig_wifi_get_profiles_count() < profiles_count) {
		DBG("profiles prev_count (%d) - profiles count (%d)",
				__netconfig_wifi_get_profiles_count(), profiles_count);

		__netconfig_wifi_add_network_notification();
	}

	__netconfig_wifi_set_profiles_count(profiles_count);
}

void netconfig_wifi_state_notifier_cleanup(void)
{
	g_slist_free_full(notifier_list, NULL);
}

void netconfig_wifi_state_notifier_register(
		struct netconfig_wifi_state_notifier *notifier)
{
	DBG("register notifier");

	notifier_list = g_slist_append(notifier_list, notifier);
}

void netconfig_wifi_state_notifier_unregister(
		struct netconfig_wifi_state_notifier *notifier)
{
	DBG("un-register notifier");

	notifier_list = g_slist_remove_all(notifier_list, notifier);
}
