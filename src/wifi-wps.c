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

#include <errno.h>
#include <vconf.h>
#include <glib.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-wps.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "netsupplicant.h"
#include "wifi-background-scan.h"

#define NETCONFIG_SSID_LEN						32
#define NETCONFIG_BSSID_LEN						6
#define NETCONFIG_WPS_DBUS_REPLY_TIMEOUT		(10 * 1000)

#define VCONF_WIFI_ALWAYS_ALLOW_SCANNING \
	"file/private/wifi/always_allow_scanning"

static gboolean netconfig_is_wps_enabled = FALSE;
static gboolean netconfig_is_device_scanning = FALSE;
static gboolean netconfig_is_wps_scan_aborted = FALSE;
static int wps_bss_list_count = 0;

struct wps_bss_info_t {
	unsigned char ssid[NETCONFIG_SSID_LEN + 1];
	unsigned char bssid[NETCONFIG_BSSID_LEN + 1];
	int ssid_len;
	int rssi;
	int mode;
};

#if defined TIZEN_TV
struct netconfig_wifi_wps {
	char *pin;
	gboolean pbc;
};

static struct netconfig_wifi_wps wifi_wps;
#endif

static GSList *wps_bss_info_list = NULL;

static void __netconfig_wps_set_mode(gboolean enable)
{
	if (netconfig_is_wps_enabled == enable)
		return;

	netconfig_is_wps_enabled = enable;
}

gboolean netconfig_wifi_is_wps_enabled(void)
{
	return netconfig_is_wps_enabled;
}


void netconfig_wifi_notify_wps_credentials(const char *ssid, const char *wps_key)
{
	GVariantBuilder *builder;
	GVariant *params;
	const char *sig_name = "WpsCredentials";
	const char *prop_ssid = "ssid";
	const char *prop_key = "key";

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", prop_ssid, g_variant_new_string(ssid));
	g_variant_builder_add(builder, "{sv}", prop_key, g_variant_new_string(wps_key));

	params = g_variant_new("(@a{sv})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	netconfig_dbus_emit_signal(NULL,
				NETCONFIG_WIFI_PATH,
				NETCONFIG_WIFI_INTERFACE,
				sig_name,
				params);

	INFO("Sent signal (%s)", sig_name);
	return;
}

void netconfig_wifi_notify_wps_completed(const char *ssid)
{
	GVariantBuilder *builder;
	GVariant *params;
	const char *sig_name = "WpsCompleted";
	const char *prop_ssid = "ssid";

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", prop_ssid, g_variant_new_string(ssid));

	params = g_variant_new("(@a{sv})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	netconfig_dbus_emit_signal(NULL,
				NETCONFIG_WIFI_PATH,
				NETCONFIG_WIFI_INTERFACE,
				sig_name,
				params);

	INFO("Sent signal (%s)", sig_name);
	return;
}

void netconfig_wifi_notify_wps_fail_event(int config_error, int error_indication)
{
	GVariantBuilder *builder;
	GVariant *params;
	const char *sig_name = "WpsFailEvent";
	const char *prop_config_error = "config_error";
	const char *prop_error_indication = "error_indication";

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", prop_config_error,
				g_variant_new_int32(config_error));
	g_variant_builder_add(builder, "{sv}", prop_error_indication,
				g_variant_new_int32(error_indication));

	params = g_variant_new("(@a{sv})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	netconfig_dbus_emit_signal(NULL,
				NETCONFIG_WIFI_PATH,
				NETCONFIG_WIFI_INTERFACE,
				sig_name,
				params);

	INFO("Sent signal (%s)", sig_name);
	return;
}

static void __netconfig_wifi_wps_notify_scan_done(void)
{
	GVariantBuilder *builder = NULL;
	GVariantBuilder *builder1 = NULL;
	GSList* list = NULL;
	const char *prop_ssid = "ssid";
	const char *prop_bssid = "bssid";
	const char *prop_rssi = "rssi";
	const char *prop_mode = "mode";

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	for (list = wps_bss_info_list; list != NULL; list = list->next) {
		struct wps_bss_info_t *bss_info = (struct wps_bss_info_t *)list->data;

		if (bss_info) {
			gchar bssid_buff[18] = { 0, };
			gchar *bssid_str = bssid_buff;
			unsigned char *ssid = (unsigned char *)bss_info->ssid;
			int ssid_len = (int)bss_info->ssid_len;
			int rssi = (int)bss_info->rssi;
			int mode = (int)bss_info->mode;
			int i = 0;
			g_snprintf(bssid_buff, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
					bss_info->bssid[0], bss_info->bssid[1], bss_info->bssid[2],
					bss_info->bssid[3], bss_info->bssid[4], bss_info->bssid[5]);

			DBG("BSS found; SSID %s, BSSID %s, RSSI %d MODE %d", ssid, bssid_str, rssi, mode);

			builder1 = g_variant_builder_new(G_VARIANT_TYPE("ay"));
			for (i = 0; i < ssid_len; i++)
				g_variant_builder_add(builder1, "y", ssid[i]);
			g_variant_builder_add(builder, "{sv}", prop_ssid, g_variant_builder_end(builder1));
			g_variant_builder_unref(builder1);

			g_variant_builder_add(builder, "{sv}", prop_bssid, g_variant_new_string(bssid_str));
			g_variant_builder_add(builder, "{sv}", prop_rssi, g_variant_new_int32(rssi));
			g_variant_builder_add(builder, "{sv}", prop_mode, g_variant_new_int32(mode));
		}
	}

	wifi_emit_wps_scan_completed((Wifi *)get_wifi_object(), g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	if (wps_bss_info_list != NULL)
		g_slist_free_full(wps_bss_info_list, g_free);

	wps_bss_info_list = NULL;
	wps_bss_list_count = 0;
	INFO("WpsScanCompleted");

	return;
}

static void __netconfig_wifi_wps_get_bss_info_result(
		GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GVariant *reply = NULL;
	GVariant *value;
	GVariantIter *iter;
	gchar *key;
	struct wps_bss_info_t *bss_info;
	GDBusConnection *conn = NULL;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION(source_object);
	reply = g_dbus_connection_call_finish(conn, res, &error);

	if (error != NULL) {
		ERR("Error code: [%d] Error message: [%s]", error->code, error->message);
		g_error_free(error);
		goto done;
	}

	bss_info = g_try_new0(struct wps_bss_info_t, 1);
	if (bss_info == NULL)
		goto done;

	g_variant_get(reply, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (key != NULL) {
			if (g_strcmp0(key, "BSSID") == 0) {
				const guchar *bssid;
				gsize bssid_len;

				bssid = g_variant_get_fixed_array(value, &bssid_len, sizeof(guchar));
				if (bssid_len == NETCONFIG_BSSID_LEN)
					memcpy(bss_info->bssid, bssid, bssid_len);
			} else if (g_strcmp0(key, "SSID") == 0) {
				const guchar *ssid;
				gsize ssid_len;

				ssid = g_variant_get_fixed_array(value, &ssid_len, sizeof(guchar));
				if (ssid != NULL && ssid_len > 0 && ssid_len <= NETCONFIG_SSID_LEN) {
					memcpy(bss_info->ssid, ssid, ssid_len);
					bss_info->ssid_len = ssid_len;
				} else {
					memset(bss_info->ssid, 0, sizeof(bss_info->ssid));
					bss_info->ssid_len = 0;
				}
			} else if (g_strcmp0(key, "Mode") == 0) {
				gchar *mode = NULL;

				g_variant_get(value, "s", &mode);
				if (mode == NULL)
					bss_info->mode = 0;
				else {
					if (g_strcmp0(mode, "infrastructure") == 0)
						bss_info->mode = 1;
					else if (g_strcmp0(mode, "ad-hoc") == 0)
						bss_info->mode = 2;
					else
						bss_info->mode = 0;
					g_free(mode);
				}
			} else if (g_strcmp0(key, "Signal") == 0) {
				gint16 signal;

				signal = g_variant_get_int16(value);
				bss_info->rssi = signal;
			}
		}
	}

	if (bss_info->ssid[0] == '\0')
		g_free(bss_info);
	else
		wps_bss_info_list = g_slist_append(wps_bss_info_list, bss_info);

	g_variant_iter_free(iter);
done:
	if (reply)
		g_variant_unref(reply);

	netconfig_gdbus_pending_call_unref();

	wps_bss_list_count--;
	if (wps_bss_list_count <= 0) {
		__netconfig_wifi_wps_notify_scan_done();

		if (netconfig_is_wps_scan_aborted == FALSE)
			wifi_power_driver_and_supplicant(FALSE);
	}
}

static void __netconfig_wifi_wps_get_bss_info(const char *path, int index)
{
	gboolean reply = FALSE;
	GVariant *param = NULL;

	param = g_variant_new("(s)", SUPPLICANT_IFACE_BSS);

	reply = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			path, DBUS_INTERFACE_PROPERTIES,
			"GetAll", param, __netconfig_wifi_wps_get_bss_info_result);
	if (reply != TRUE)
		ERR("Fail to invoke_dbus_method_nonblock GetAll");

	return;
}

static void __netconfig_wifi_wps_get_bsss_result(GObject *source_object,
		GAsyncResult *res, gpointer user_data)
{
	GVariant *reply = NULL;
	GVariant *value = NULL;
	GVariantIter *iter = NULL;
	GDBusConnection *conn = NULL;
	gchar *path = NULL;
	gboolean counter_flag = FALSE;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION(source_object);
	reply = g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		ERR("Error code: [%d] Error message: [%s]", error->code, error->message);
		g_error_free(error);
		goto done;
	}

	g_variant_get(reply, "(v)", &value);
	if (g_variant_is_of_type(value, G_VARIANT_TYPE_OBJECT_PATH_ARRAY)) {
		g_variant_get(value, "ao", &iter);
		while (g_variant_iter_next(iter, "o", &path)) {
			if (path != NULL && g_strcmp0(path, "/") != 0) {
				__netconfig_wifi_wps_get_bss_info(path, ++wps_bss_list_count);

				counter_flag = TRUE;
			}

			if (path)
				g_free(path);
		}
	}

	if (iter)
		g_variant_iter_free(iter);

	if (value)
		g_variant_unref(value);

done:
	if (reply)
		g_variant_unref(reply);

	netconfig_gdbus_pending_call_unref();

	/* Send WpsScanCompleted signal even when the BSS count is 0 */
	if (wps_bss_list_count <= 0 && counter_flag == FALSE) {
		__netconfig_wifi_wps_notify_scan_done();

		if (netconfig_is_wps_scan_aborted == FALSE)
			wifi_power_driver_and_supplicant(FALSE);
	}
}

static int _netconfig_wifi_wps_get_bsss(void)
{
	gboolean reply = FALSE;
	const char *if_path = NULL;
	GVariant *params = NULL;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		return -ESRCH;
	}

	params = g_variant_new("(ss)", SUPPLICANT_IFACE_INTERFACE, "BSSs");

	reply = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			if_path, DBUS_INTERFACE_PROPERTIES,
			"Get", params, __netconfig_wifi_wps_get_bsss_result);
	if (reply != TRUE) {
		ERR("Fail to method: Get");

		return -ESRCH;
	}

	return 0;
}

void netconfig_wifi_wps_signal_scandone(void)
{
	wps_bss_list_count = 0;
	_netconfig_wifi_wps_get_bsss();

	netconfig_is_device_scanning = FALSE;

	__netconfig_wps_set_mode(FALSE);
}

void netconfig_wifi_wps_signal_scanaborted(void)
{
	wps_bss_list_count = 0;
	netconfig_is_wps_scan_aborted = TRUE;
	_netconfig_wifi_wps_get_bsss();

	netconfig_is_device_scanning = FALSE;

	__netconfig_wps_set_mode(FALSE);
}

static int __netconfig_wifi_wps_request_scan(const char *if_path)
{
	GDBusConnection *connection = NULL;
	GVariant *message = NULL;
	GVariantBuilder *builder = NULL;
	const char *key1 = "Type";
	const char *val1 = "passive";

	if (if_path == NULL)
		if_path = netconfig_wifi_get_supplicant_interface();

	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		return -ESRCH;
	}

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("Failed to get GDBusconnection");
		return -EIO;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", key1, g_variant_new_string(val1));
	message = g_variant_new("(@a{sv})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	g_dbus_connection_call(connection,
			SUPPLICANT_SERVICE,
			if_path,
			SUPPLICANT_INTERFACE ".Interface",
			"Scan",
			message,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_WPS_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			NULL,
			NULL);

	netconfig_is_device_scanning = TRUE;

	g_variant_unref(message);
	/* Clear bss_info_list for the next scan result */
	if (wps_bss_info_list) {
		g_slist_free_full(wps_bss_info_list, g_free);
		wps_bss_info_list = NULL;
	}

	netconfig_is_wps_scan_aborted = FALSE;

	return 0;
}

static void __netconfig_wifi_interface_create_result(
		GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GVariant *message;
	gchar *path = NULL;
	GDBusConnection *conn = NULL;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION(source_object);

	message = g_dbus_connection_call_finish(conn, res, &error);
	if (error == NULL) {
		g_variant_get(message, "(o)", &path);

		if (path) {
			__netconfig_wifi_wps_request_scan(path);
			g_free(path);
		}
	}
	else if (NULL != strstr(error->message, ".InterfaceExists")) {
		INFO("Error Message %s %s", error->message, path);
		g_variant_get(message, "(o)", &path);
		if (path) {
			__netconfig_wifi_wps_request_scan(path);
			g_free(path);
		}
		else
			__netconfig_wifi_wps_request_scan(NULL);
	} else {
		ERR("Failed to create interface, Error: %d[%s]", error->code, error->message);
		__netconfig_wps_set_mode(FALSE);
		wifi_power_driver_and_supplicant(FALSE);
	}

	g_variant_unref(message);
}

static int  __netconfig_wifi_wps_create_interface(void)
{
	GDBusConnection *connection = NULL;
	GVariant *message = NULL;
	GVariantBuilder *builder = NULL;
	const char *key = "Ifname";
	const char *val = WIFI_IFNAME;

	connection = netdbus_get_connection();
	if (connection == NULL) {
		DBG("Failed to get GDBusconnection");
		return -EIO;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", key, g_variant_new_string(val));
	message = g_variant_new("(@a{sv})", g_variant_builder_end(builder));

	g_dbus_connection_call(connection,
			SUPPLICANT_SERVICE,
			SUPPLICANT_PATH,
			SUPPLICANT_INTERFACE,
			"CreateInterface",
			message,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_WPS_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			(GAsyncReadyCallback) __netconfig_wifi_interface_create_result,
			NULL);

	g_variant_unref(message);

	return 0;
}

static int __netconfig_wifi_wps_scan(void)
{
	int err = 0;
	wifi_tech_state_e wifi_tech_state;

	if (netconfig_is_device_scanning == TRUE)
		return -EINPROGRESS;

	wifi_tech_state = wifi_state_get_technology_state();
	if (wifi_tech_state <= NETCONFIG_WIFI_TECH_OFF)
		err = wifi_power_driver_and_supplicant(TRUE);

	if (err < 0 && err != -EALREADY)
		return err;

	netconfig_is_device_scanning = TRUE;

	DBG("WPS scan requested");
	if (wifi_tech_state >= NETCONFIG_WIFI_TECH_POWERED) {
		if (netconfig_wifi_get_scanning() == TRUE)
			return -EINPROGRESS;

		netconfig_wifi_bgscan_start(TRUE);

		if (wifi_tech_state == NETCONFIG_WIFI_TECH_CONNECTED)
			__netconfig_wifi_wps_request_scan(NULL);
	} else {
		err = __netconfig_wifi_wps_create_interface();
	}

	return err;
}

gboolean handle_request_wps_scan(Wifi *wifi, GDBusMethodInvocation *context)
{
	int err, enabled = 0;
	wifi_tech_state_e tech_state;

	g_return_val_if_fail(wifi != NULL, FALSE);

	if (netconfig_is_wifi_tethering_on() == TRUE) {
		ERR("Wi-Fi Tethering is enabled");
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_NO_SERVICE, "TetheringEnabled");
		return -EBUSY;
	}

#if !defined TIZEN_WEARABLE
	if (netconfig_wifi_is_bgscan_paused()) {
		ERR("Scan is paused");
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_NO_SERVICE, "ScanPaused");
		return FALSE;
	}
#endif

	tech_state = wifi_state_get_technology_state();
	if (tech_state <= NETCONFIG_WIFI_TECH_OFF) {
#if !defined TIZEN_WEARABLE
		netconfig_vconf_get_int(VCONF_WIFI_ALWAYS_ALLOW_SCANNING, &enabled);
#else
		enabled = 0;
#endif

		if (enabled == 0) {
			netconfig_error_permission_denied(context);
			return FALSE;
		}
	}

	__netconfig_wps_set_mode(TRUE);

	err = __netconfig_wifi_wps_scan();
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_inprogress(context);
		else
			netconfig_error_wifi_driver_failed(context);

		return FALSE;
	}

	wifi_complete_request_wps_scan(wifi, context);
	return TRUE;
}

#if defined TIZEN_TV

static void interface_wps_start_result(GObject *source_object,
			GAsyncResult *res, gpointer user_data)
{
	GVariant *reply;
	GDBusConnection *conn = NULL;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION (source_object);
	reply = g_dbus_connection_call_finish(conn, res, &error);

	if (reply == NULL) {
		if (error != NULL) {
			ERR("Fail to request status [%d: %s]",
					error->code, error->message);
			g_error_free(error);
		} else {
			ERR("Fail to request status");
		}
	} else {
		DBG("Successfully M/W--->WPAS: Interface.WPS.Start Method");
	}

	g_variant_unref(reply);
	netconfig_gdbus_pending_call_unref();
}

static void __netconfig_wifi_invoke_wps_connect(GObject *source_object,
			GAsyncResult *res, gpointer user_data)
{
	GVariant *message = NULL;
	GVariantBuilder *builder = NULL;
	const char *role = "enrollee", *type, *key;
	const char *if_path = NULL;
	gboolean reply = FALSE;

	if (if_path == NULL)
		if_path = netconfig_wifi_get_supplicant_interface();

	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		return;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));

	key = "Role";
	g_variant_builder_add(builder, "{sv}", key, g_variant_new_string(role));

	key = "Type";
	if(wifi_wps.pbc == TRUE){
		type = "pbc";
	}else
		type = "pin";
	g_variant_builder_add(builder, "{sv}", key, g_variant_new_string(type));

	if(wifi_wps.pin != NULL){
		key="Pin";
		g_variant_builder_add(builder, "{sv}", key, g_variant_new_string(wifi_wps.pin));
	}
	message = g_variant_new("(@a{sv})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	DBG("[net-config]: TizenMW-->WPAS: .Interface.WPS.Start");
        reply = netconfig_supplicant_invoke_dbus_method_nonblock(
			SUPPLICANT_SERVICE,
                        if_path,
			SUPPLICANT_IFACE_WPS,
			"Start",
                        message,
			(GAsyncReadyCallback) interface_wps_start_result);

	if (reply != TRUE) {
		ERR("Fail to Scan");
	}

	return;
}

static gboolean __netconfig_wifi_invoke_wps_process_credentials(const char *object_path)
{
	gboolean reply = FALSE;
	GVariant *params = NULL;
	const char *interface = SUPPLICANT_IFACE_WPS;
	const char *key = "ProcessCredentials";
	gboolean credentials = TRUE;
	GVariant *var = NULL;

	 var = g_variant_new_boolean(credentials);
	params = g_variant_new("(ssv)", interface, key, var);

	ERR("[net-config]: TizenMW-->WPAS: .Set");
	reply = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			object_path, DBUS_INTERFACE_PROPERTIES,
			"Set", params, __netconfig_wifi_invoke_wps_connect);

	if (reply != TRUE)
		ERR("M/W--->WPAS: Interface.WPS.Set Method Failed");

	return reply;
}

gboolean netconfig_wifi_wps_connect()
{
	const char *if_path = NULL;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		 return FALSE;
	}

	if (__netconfig_wifi_invoke_wps_process_credentials(if_path) == TRUE) {
		ERR("Wi-Fi WPS Connect started");

		return TRUE;
	}

	return FALSE;
}

static void __interface_wps_cancel_result(GObject *source_object,
			GAsyncResult *res, gpointer user_data)
{
	GVariant *reply;
	GDBusConnection *conn = NULL;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION (source_object);
	reply = g_dbus_connection_call_finish(conn, res, &error);

	if (reply == NULL) {
		if (error != NULL) {
			ERR("Fail to request status [%d: %s]",
					error->code, error->message);
			g_error_free(error);
		} else {
			ERR("Fail torequest status");
		}
	} else {
		DBG("Successfully M/W--->WPAS: Interface.WPS.Cancel Method");
	}

	g_variant_unref(reply);
	netconfig_gdbus_pending_call_unref();
}

static gboolean __netconfig_wifi_invoke_wps_cancel()
{
	gboolean reply = FALSE;
	const char *if_path = NULL;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		return -ESRCH;
	}

	DBG("M/W--->WPAS: Interface.WPS.Cancel Method");

	reply = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			if_path, SUPPLICANT_IFACE_WPS,
			"Cancel", NULL, __interface_wps_cancel_result);

	if (reply != TRUE)
		ERR("M/W--->WPAS: Interface.WPS.Cancel Method Failed");

	return reply;
}

gboolean netconfig_get_wps_field()
{
	return wifi_wps.pbc;
}
#endif

gboolean handle_request_wps_cancel(Wifi *wifi, GDBusMethodInvocation *context)
{
#if defined TIZEN_TV
	ERR("Received WPS PBC Cancel Request");
	g_return_val_if_fail(wifi != NULL, FALSE);
	__netconfig_wifi_invoke_wps_cancel();

	wifi_complete_request_wps_cancel(wifi, context);
	return TRUE;
#else
	/*Not supported for mobile and Wearable profile*/
	wifi_complete_request_wps_cancel(wifi, context);
	return FALSE;
#endif
}

gboolean handle_request_wps_connect(Wifi *wifi, GDBusMethodInvocation *context, gchar *param)
{
#if defined TIZEN_TV

	ERR("Received WPS PBC/PIN Connection Request");

	g_return_val_if_fail(wifi != NULL, FALSE);

	/* Checking the value of pin if param have a string "PBC"
	 * in that scenario PBC will trigger otherwise PIN Connection */

	if(g_strcmp0(param, "PBC") == 0){
		wifi_wps.pbc = TRUE;
		wifi_wps.pin = NULL;
	}
	else{
		wifi_wps.pin = g_strdup(param);
		wifi_wps.pbc = FALSE;
	}

	netconfig_wifi_wps_connect();

	wifi_complete_request_wps_connect(wifi, context);
	return TRUE;
#else
	/*Tizen Mobile & Wearable Profile does not support
		this feature*/
	wifi_complete_request_wps_connect(wifi, context);
	return FALSE;
#endif
}
