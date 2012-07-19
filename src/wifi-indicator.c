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

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/wireless.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "dbus.h"
#include "util.h"
#include "wifi-indicator.h"

#define NETCONFIG_WIFI_INDICATOR_UPDATE_INTERVAL	3

#define VCONFKEY_WIFI_SNR_MIN				-85
#define VCONFKEY_WIFI_SNR_MAX				-55
#define NETCONFIG_WIFI_WEAK_SIGNAL			-85

static guint netconfig_wifi_indicator_timer = 0;

static GList *__netconfig_wifi_supplicant_setup(GList * list,
		struct dbus_input_arguments *items)
{
	struct dbus_input_arguments *iter = items;

	if (iter == NULL)
		return NULL;

	while (iter->data) {
		list = g_list_append(list, iter);
		iter++;
	}

	return list;
}

static int __netconfig_wifi_get_interface(const char **path)
{
	char *ptr = (char *)*path;
	DBusConnection *conn = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int MessageType = 0;
	const char *temp = NULL;

	GList *input_args = NULL;
	struct dbus_input_arguments inserted_items[] = {
		{DBUS_TYPE_STRING, SUPPLICANT_INTERFACE},
		{DBUS_TYPE_STRING, "Interfaces"},
		{0, NULL}
	};

	if (ptr == NULL) {
		ERR("Error!!! path is NULL");
		return -1;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Error!!! Can't get on system bus");
		return -1;
	}

	input_args = __netconfig_wifi_supplicant_setup(input_args, inserted_items);

	message = netconfig_supplicant_invoke_dbus_method(SUPPLICANT_SERVICE, conn,
				SUPPLICANT_PATH,
				SUPPLICANT_GLOBAL_INTERFACE, "Get",
				input_args);

	g_list_free(input_args);

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto err;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", err_msg);
		goto err;
	}

	dbus_message_iter_init(message, &iter);
	if ((MessageType = dbus_message_iter_get_arg_type(&iter)) == DBUS_TYPE_VARIANT) {
		DBusMessageIter array;
		dbus_message_iter_recurse(&iter, &array);

		if ((MessageType = dbus_message_iter_get_arg_type(&array)) == DBUS_TYPE_ARRAY) {
			DBusMessageIter object_path;
			dbus_message_iter_recurse(&array, &object_path);

			if ((MessageType = dbus_message_iter_get_arg_type(&object_path)) == DBUS_TYPE_OBJECT_PATH)
				dbus_message_iter_get_basic(&object_path, &temp);
			else
				goto err;

		} else
			goto err;

	} else
		goto err;

	INFO("interface %s, path pointer %p", temp, *path);
	g_strlcpy(ptr, temp, DBUS_PATH_MAX_BUFLEN);

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	return 0;

err:
	if (message != NULL)
		dbus_message_unref(message);

	if (conn != NULL)
		dbus_connection_unref(conn);

	return -1;
}

#ifdef NL80211
static int __netconfig_wifi_get_signal(const char *path, int *sig)
{
	DBusConnection *conn = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int MessageType = 0;

	if (path == NULL || sig == NULL) {
		ERR("Error!!! path is NULL");
		return -1;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Error!!! Can't get on system bus");
		return -1;
	}

	INFO("supplicant path is [%s]", path);

	message = netconfig_supplicant_invoke_dbus_method(SUPPLICANT_SERVICE, conn,
				path,
				SUPPLICANT_INTERFACE".Interface", "GetLinkSignal",
				NULL);

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto err;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", err_msg);
		goto err;
	}

	dbus_message_iter_init(message, &iter);

	if ((MessageType = dbus_message_iter_get_arg_type(&iter)) == DBUS_TYPE_INT32) {
		dbus_message_iter_get_basic(&iter, sig);
		INFO("signal value is [%d]", *sig);
	} else {
		ERR("message type is %d", MessageType);
		goto err;
	}

	dbus_message_unref(message);

	dbus_connection_unref(conn);

	return 0;

err:
	if (message != NULL)
		dbus_message_unref(message);

	if (conn != NULL)
		dbus_connection_unref(conn);

	return -1;
}
#endif

static int __netconfig_wifi_set_rssi_level(gboolean is_start, const char *ifname)
{
	int rssi_dbm = 0;
	static int last_snr = 0;
	int snr_level_interval = 0;
	int snr_level = 0;

#ifndef NL80211
	int fd = -1;
	struct iwreq wifi_req;
	struct iw_statistics stats;

	unsigned int iw_stats_len = sizeof(struct iw_statistics);

	/* Set device name */
	memset(wifi_req.ifr_name, 0, sizeof(wifi_req.ifr_name));
	strncpy(wifi_req.ifr_name, ifname, sizeof(wifi_req.ifr_name) - 1);
	wifi_req.ifr_name[sizeof(wifi_req.ifr_name) - 1] = '\0';

	wifi_req.u.data.pointer = (caddr_t) &stats;
	wifi_req.u.data.length = iw_stats_len;
	wifi_req.u.data.flags = 1;	/* Clear updated flag */

	if (is_start == TRUE) {
		last_snr = VCONFKEY_WIFI_STRENGTH_MAX;
		vconf_set_int(VCONFKEY_WIFI_STRENGTH, last_snr);
		return 0;
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		DBG("Fail to open socket to get rssi");
		return -1;
	}

	memset(&stats, 0, iw_stats_len);

	if (ioctl(fd, SIOCGIWSTATS, &wifi_req) < 0) {
		DBG("Fail to execute ioctl for SIOCGIWSTATS");
		close(fd);
		return -1;
	}
	close(fd);

	rssi_dbm = stats.qual.level - 255; /** signed integer, so 255 */
#else
	if (is_start == TRUE) {
		last_snr = VCONFKEY_WIFI_STRENGTH_MAX;
		vconf_set_int(VCONFKEY_WIFI_STRENGTH, last_snr);
		return 0;
	}
	__netconfig_wifi_get_signal(ifname, &rssi_dbm);
#endif

	snr_level_interval =
		(VCONFKEY_WIFI_SNR_MAX -
		 VCONFKEY_WIFI_SNR_MIN) / (VCONFKEY_WIFI_STRENGTH_MAX - 2);

	snr_level =
		((rssi_dbm - VCONFKEY_WIFI_SNR_MIN) / snr_level_interval) + 2;

	if (rssi_dbm <= VCONFKEY_WIFI_SNR_MIN)
		snr_level = VCONFKEY_WIFI_STRENGTH_MIN + 1;
	else if (rssi_dbm >= VCONFKEY_WIFI_SNR_MAX)
		snr_level = VCONFKEY_WIFI_STRENGTH_MAX;

	if (snr_level != last_snr) {
		INFO("rssi (%d)", rssi_dbm);
		vconf_set_int(VCONFKEY_WIFI_STRENGTH, snr_level);
		last_snr = snr_level;
	}

	return 0;
}

#ifndef NL80211
static int __netconfig_wifi_get_ifname(const char *supp_inf, const char **ifname)
{
	char *ptr = (char *)*ifname;
	DBusConnection *conn = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int MessageType = 0;
	const char *temp = NULL;

	GList *input_args = NULL;

	struct dbus_input_arguments inserted_items[] = {
			{ DBUS_TYPE_STRING, SUPPLICANT_INTERFACE ".Interface" },
			{ DBUS_TYPE_STRING, "Ifname" },
			{ 0, NULL }
	};

	if (ptr == NULL) {
		ERR("Error!!! Path is NULL");
		return -1;
	}

	if (supp_inf == NULL) {
		ERR("Error!!! Supplicant DBus interface is NULL");
		return -1;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		ERR("Fail to get DBus *p", conn);
		return -1;
	}

	input_args = __netconfig_wifi_supplicant_setup(input_args, inserted_items);

	message = netconfig_supplicant_invoke_dbus_method(SUPPLICANT_SERVICE, conn, (char *)supp_inf,
				SUPPLICANT_GLOBAL_INTERFACE, "Get",
				input_args);

	g_list_free(input_args);

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto err;
	}

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto err;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", err_ptr);
		goto err;
	}

	dbus_message_iter_init(message, &iter);

	if ((MessageType = dbus_message_iter_get_arg_type(&iter)) == DBUS_TYPE_VARIANT) {
		DBusMessageIter string_type;
		dbus_message_iter_recurse(&iter, &string_type);

		if ((MessageType = dbus_message_iter_get_arg_type(&string_type)) ==
				DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&string_type, &temp);
		} else
			goto err;

	} else
		goto err;

	INFO("interface %s, ifname pointer %p", temp, *ifname);

	g_strlcpy(ptr, temp, IFNAMSIZ);

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	return 0;

err:
	if (message != NULL)
		dbus_message_unref(message);

	if (conn != NULL)
		dbus_connection_unref(conn);

	return -1;
}
#endif

static gboolean __netconfig_wifi_monitor_rssi(gpointer data)
{
	int rssi_result = 0;

	if (data == NULL)
		return FALSE;

	rssi_result = __netconfig_wifi_set_rssi_level(FALSE, (char *)data);

	if (rssi_result == -1)
		vconf_set_int(VCONFKEY_WIFI_STRENGTH, VCONFKEY_WIFI_STRENGTH_MIN);

	return TRUE;
}

void netconfig_wifi_indicator_start(void)
{
	char *path_ptr = NULL;
	static char path[DBUS_PATH_MAX_BUFLEN] = { 0 };
#ifndef NL80211
	char *ifname_ptr = NULL;
	static char ifname[IFNAMSIZ] = { 0 };
#endif

	INFO("Start Wi-Fi indicator");

	netconfig_stop_timer(&netconfig_wifi_indicator_timer);

#ifndef NL80211
	memset(ifname, 0, sizeof(ifname));
	ifname_ptr = &ifname[0];
#endif
	path_ptr = &path[0];

	if (__netconfig_wifi_get_interface((const char **)(&path_ptr)) == 0) {
#ifndef NL80211
		INFO("Success to get DBus interface %s", path_ptr);

		if (__netconfig_wifi_get_ifname(path_ptr, (const char **)(&ifname_ptr)) == 0) {
			INFO("Success to get wifi ifname %s", ifname_ptr);

			__netconfig_wifi_set_rssi_level(TRUE, (const char *)ifname);

			DBG("Register Wi-Fi indicator timer with %d seconds",
					NETCONFIG_WIFI_INDICATOR_UPDATE_INTERVAL);
			netconfig_start_timer_seconds(NETCONFIG_WIFI_INDICATOR_UPDATE_INTERVAL,
					__netconfig_wifi_monitor_rssi, ifname, &netconfig_wifi_indicator_timer);
		}

		return;
#else
		INFO("interface is [%s]", path_ptr);

		__netconfig_wifi_set_rssi_level(TRUE, (const char *)path_ptr);

		DBG("Register Wi-Fi indicator timer with %d seconds",
				NETCONFIG_WIFI_INDICATOR_UPDATE_INTERVAL);
		netconfig_start_timer_seconds(NETCONFIG_WIFI_INDICATOR_UPDATE_INTERVAL,
				__netconfig_wifi_monitor_rssi, path_ptr, &netconfig_wifi_indicator_timer);

		return;
#endif
	}
}

void netconfig_wifi_indicator_stop(void)
{
	INFO("Stop Wi-Fi indicator");

	vconf_set_int(VCONFKEY_WIFI_STRENGTH, VCONFKEY_WIFI_STRENGTH_MAX);

	netconfig_stop_timer(&netconfig_wifi_indicator_timer);
}
