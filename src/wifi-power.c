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
#include <unistd.h>
#include <vconf.h>
#include <vconf-keys.h>
#include <wifi-direct.h>

#include "log.h"
#include "wifi.h"
#include "dbus.h"
#include "util.h"
#include "neterror.h"
#include "netconfig.h"
#include "emulator.h"
#include "wifi-state.h"
#include "wifi-background-scan.h"

gboolean netconfig_iface_wifi_load_driver(NetconfigWifi *wifi, GError **error);
gboolean netconfig_iface_wifi_remove_driver(NetconfigWifi *wifi, GError **error);

#include "netconfig-iface-wifi-glue.h"

#define NETCONFIG_WIFI_PATH	"/net/netconfig/wifi"

#define WLAN_DRIVER_SCRIPT "/usr/bin/wlan.sh"

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL

enum {
	PROP_O,
	PROP_WIFI_CONN,
	PROP_WIFI_PATH,
};

enum {
	SIG_WIFI_DRIVER,
	SIG_LAST
};

struct NetconfigWifiClass {
	GObjectClass parent;

	/* method and signals */
	void (*driver_loaded) (NetconfigWifi *wifi, gchar *mac);
};

struct NetconfigWifi {
	GObject parent;

	/* member variable */
	DBusGConnection *conn;
	gchar *path;
};

static guint32 signals[SIG_LAST] = { 0, };

G_DEFINE_TYPE(NetconfigWifi, netconfig_wifi, G_TYPE_OBJECT);


static void __netconfig_wifi_gobject_get_property(GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	return;
}

static void __netconfig_wifi_gobject_set_property(GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	NetconfigWifi *wifi = NETCONFIG_WIFI(object);

	switch (prop_id) {
	case PROP_WIFI_CONN:
	{
		wifi->conn = g_value_get_boxed(value);
		INFO("wifi(%p) set conn(%p)", wifi, wifi->conn);
		break;
	}

	case PROP_WIFI_PATH:
	{
		if (wifi->path)
			g_free(wifi->path);

		wifi->path = g_value_dup_string(value);
		INFO("wifi(%p) path(%s)", wifi, wifi->path);

		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_wifi_init(NetconfigWifi *wifi)
{
	DBG("wifi initialize");

	wifi->conn = NULL;
	wifi->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_wifi_class_init(NetconfigWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	DBG("class initialize");

	object_class->get_property = __netconfig_wifi_gobject_get_property;
	object_class->set_property = __netconfig_wifi_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_WIFI,
			&dbus_glib_netconfig_iface_wifi_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_WIFI_CONN,
			g_param_spec_boxed("conn", "CONNECTION", "DBus connection",
				DBUS_TYPE_G_CONNECTION,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property(object_class, PROP_WIFI_PATH,
			g_param_spec_string("path", "PATH", "Object Path",
				PROP_DEFAULT_STR,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signal */
	signals[SIG_WIFI_DRIVER] = g_signal_new("driver-loaded",
			G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET(NetconfigWifiClass,
				driver_loaded),
			NULL, NULL,
			g_cclosure_marshal_VOID__STRING,
			G_TYPE_NONE, 1, G_TYPE_STRING);
}


static gboolean __netconfig_wifi_enable_technology(void)
{
	DBusMessage *reply = NULL;
	char path[DBUS_PATH_MAX_BUFLEN] = "/";
	char request[] = CONNMAN_MANAGER_INTERFACE ".EnableTechnology";
	char param1[] = "string:wifi";
	char *param_array[] = {
		NULL,
		NULL,
		NULL,
		NULL
	};

	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = param1;

	reply = netconfig_dbus_send_request(CONNMAN_SERVICE, param_array);
	if (reply == NULL) {
		ERR("Error! Request failed");

		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static gboolean __netconfig_wifi_disable_technology(void)
{
	DBusMessage *reply = NULL;
	char path[DBUS_PATH_MAX_BUFLEN] = "/";
	char request[] = CONNMAN_MANAGER_INTERFACE ".DisableTechnology";
	char param1[] = "string:wifi";
	char *param_array[] = {
		NULL,
		NULL,
		NULL,
		NULL
	};

	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = param1;

	reply = netconfig_dbus_send_request(CONNMAN_SERVICE, param_array);
	if (reply == NULL) {
		ERR("Error! Request failed");

		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static gboolean __netconfig_wifi_load_driver(void)
{
	gboolean rv = FALSE;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "wlan.sh", "start" };
	char *const envs[] = { NULL };

	if (netconfig_emulator_is_emulated() == TRUE)
		return rv;

	rv = netconfig_execute_file(path, args, envs);
	if (rv != TRUE) {
		DBG("failed to load wireless device driver");
		return FALSE;
	}

	DBG("Successfully loaded wireless device drivers");
	return TRUE;
}

static gboolean __netconfig_wifi_remove_driver(void)
{
	gboolean rv = FALSE;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "wlan.sh", "stop" };
	char *const env[] = { NULL };

	if (netconfig_emulator_is_emulated() == TRUE)
		return rv;

	rv = netconfig_execute_file(path, args, env);
	if (rv != TRUE) {
		DBG("failed to remove(unload) driver for wireless device");
		return FALSE;
	}

	DBG("Successfully removed(unloaded) wireless driver");
	return TRUE;
}

static gboolean __netconfig_wifi_try_to_load_driver(void);
static gboolean __netconfig_wifi_try_to_remove_driver(void);

static void __netconfig_wifi_direct_state_cb(int error_code,
		wifi_direct_device_state_e device_state, void *user_data)
{
	wifi_direct_unset_device_state_changed_cb();
	wifi_direct_deinitialize();

	if (device_state == WIFI_DIRECT_DEVICE_STATE_DEACTIVATED) {
		__netconfig_wifi_try_to_load_driver();

		return;
	}

	/* TODO: error report */
}

static gboolean __netconfig_wifi_direct_power_off(void)
{
	DBG("Wi-Fi direct is turning off");

	if (wifi_direct_initialize() < 0)
		return FALSE;

	if (wifi_direct_set_device_state_changed_cb(
			__netconfig_wifi_direct_state_cb, NULL) < 0)
		return FALSE;

	if (wifi_direct_deactivate() < 0)
		return FALSE;

	return TRUE;
}

static gboolean __netconfig_wifi_try_to_load_driver(void)
{
	int count = 0;
	gchar *wifi_tech_state = NULL;

	if (netconfig_is_wifi_tethering_on() == TRUE) {
		/* TODO: Wi-Fi tethering turns off here */
		/* return TRUE; */
		return FALSE;
	}

	if (netconfig_is_wifi_direct_on() == TRUE) {
		if (__netconfig_wifi_direct_power_off() == TRUE)
			return TRUE;
		else
			return FALSE;
	}

	if (__netconfig_wifi_load_driver() != TRUE) {
		__netconfig_wifi_remove_driver();

		return FALSE;
	}

	for (count = 0; count < 3; count++) {
		__netconfig_wifi_enable_technology();

		wifi_tech_state = netconfig_wifi_get_technology_state();
		INFO("Wi-Fi technology state: %s", wifi_tech_state);

		if (g_str_equal(wifi_tech_state, "EnabledTechnologies") == TRUE) {
			netconfig_wifi_update_power_state(TRUE);

			netconfig_wifi_device_picker_service_start();

			return TRUE;
		}

		g_free(wifi_tech_state);

		wifi_tech_state = NULL;
	}

	__netconfig_wifi_try_to_remove_driver();

	return FALSE;
}

static gboolean __netconfig_wifi_try_to_remove_driver(void)
{
	int count = 0;
	gchar *wifi_tech_state = NULL;

	netconfig_wifi_device_picker_service_stop();

	for (count = 0; count < 3; count++) {
		__netconfig_wifi_disable_technology();

		wifi_tech_state = netconfig_wifi_get_technology_state();
		INFO("Wi-Fi technology state: %s", wifi_tech_state);

		if (g_str_equal(wifi_tech_state, "EnabledTechnologies") != TRUE) {
			netconfig_wifi_update_power_state(FALSE);

			return __netconfig_wifi_remove_driver();
		}

		g_free(wifi_tech_state);

		wifi_tech_state = NULL;
	}

	return __netconfig_wifi_remove_driver();
}

static void __netconfig_wifi_airplane_mode(keynode_t* node,
		void* user_data)
{
	int value = 0;
	int wifi_state = 0;
	static gboolean powered_off_by_flightmode = FALSE;

	vconf_get_bool(VCONFKEY_SETAPPL_FLIGHT_MODE_BOOL, &value);
	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

	DBG("flight mode %s", value > 0 ? "ON" : "OFF");
	DBG("Wi-Fi state %d, Wi-Fi was off by flight mode %s",
			wifi_state, powered_off_by_flightmode == TRUE ? "Yes" : "No");

	if (value > 0) {
		/* flight mode enabled */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		DBG("Turning Wi-Fi off");

		__netconfig_wifi_try_to_remove_driver();

		powered_off_by_flightmode = TRUE;
	} else if (value == 0) {
		/* flight mode disabled */
		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		if (powered_off_by_flightmode != TRUE)
			return;

		__netconfig_wifi_try_to_load_driver();

		powered_off_by_flightmode = FALSE;
	} else
		DBG("Invalid value (%d)", value);
}

static void __netconfig_wifi_pm_state_mode(keynode_t* node,
		void* user_data)
{
	int value = -1;
	int wifi_state = 0;
	static int prev_state = VCONFKEY_PM_STATE_NORMAL;

	/*** vconf-keys.h ***
	 * 		VCONFKEY_PM_STATE_NORMAL = 1,
	 * 		VCONFKEY_PM_STATE_LCDDIM,
	 * 		VCONFKEY_PM_STATE_LCDOFF,
	 * 		VCONFKEY_PM_STATE_SLEEP
	 */

	if(vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state) == 0) {
		DBG("wifi state : %d (0 off / 1 on / 2 connected)", wifi_state);
		if(wifi_state <= VCONFKEY_WIFI_OFF)
			return;
	}

	if(vconf_get_int(VCONFKEY_PM_STATE, &value) < 0) {
		ERR("VCONFKEY_PM_STATE get failed");
		return;
	}

	DBG("Old state: %d, current: %d", prev_state, value);

	if((value == VCONFKEY_PM_STATE_NORMAL) && (prev_state >= VCONFKEY_PM_STATE_LCDOFF)) {
		DBG("PM state : Wake UP!");

		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start();
	}

	prev_state = value;
}

static void __netconfig_wifi_power_configuration(void)
{
	int wifi_last_power_state = 0;

	vconf_notify_key_changed(VCONFKEY_SETAPPL_FLIGHT_MODE_BOOL,
			__netconfig_wifi_airplane_mode, NULL);

	vconf_notify_key_changed(VCONFKEY_PM_STATE,
			__netconfig_wifi_pm_state_mode, NULL);

	vconf_get_int(VCONF_WIFI_LAST_POWER_STATE, &wifi_last_power_state);

	if (wifi_last_power_state == WIFI_POWER_ON) {
		DBG("Turn Wi-Fi on automatically");

		__netconfig_wifi_try_to_load_driver();
	}
}

gpointer netconfig_wifi_create_and_init(DBusGConnection *conn)
{
	GObject *object;

	g_return_val_if_fail(conn != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_WIFI, "conn", conn, "path",
			NETCONFIG_WIFI_PATH, NULL);

	INFO("create wifi(%p)", object);

	dbus_g_connection_register_g_object(conn, NETCONFIG_WIFI_PATH, object);

	INFO("wifi(%p) register DBus path(%s)", object, NETCONFIG_WIFI_PATH);

	__netconfig_wifi_power_configuration();

	return object;
}

gboolean netconfig_iface_wifi_load_driver(NetconfigWifi *wifi, GError **error)
{
	DBG("Wi-Fi turned on");

	g_return_val_if_fail(wifi != NULL, FALSE);

	if (__netconfig_wifi_try_to_load_driver() != TRUE) {
		netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}

gboolean netconfig_iface_wifi_remove_driver(NetconfigWifi *wifi, GError **error)
{
	DBG("Wi-Fi turned off");

	g_return_val_if_fail(wifi != NULL, FALSE);

	if (__netconfig_wifi_try_to_remove_driver() != TRUE) {
		netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}
