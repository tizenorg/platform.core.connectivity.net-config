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
#include "neterror.h"
#include "emulator.h"
#include "network-state.h"

#define NETCONFIG_NETWORK_STATE_PATH	"/net/netconfig/network"

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR   NULL


gboolean netconfig_iface_network_state_update_default_connection_info(
		NetconfigNetworkState *master,
		gchar *connection_type, gchar *connection_state,
		gchar *ip_addr, gchar *proxy_addr, GError **error);

#include "netconfig-iface-network-state-glue.h"

enum {
	PROP_O,
	PROP_NETWORK_STATE_CONN,
	PROP_NETWORK_STATE_PATH,
};

struct NetconfigNetworkStateClass {
	GObjectClass parent;
};

struct NetconfigNetworkState {
	GObject parent;

	DBusGConnection *conn;
	gchar *path;
};

G_DEFINE_TYPE(NetconfigNetworkState, netconfig_network_state, G_TYPE_OBJECT);


static void __netconfig_network_state_gobject_get_property(GObject *object,
		guint prop_id, GValue *value, GParamSpec *pspec)
{
	return;
}

static void __netconfig_network_state_gobject_set_property(GObject *object,
		guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NetconfigNetworkState *network_state = NETCONFIG_NETWORK_STATE(object);

	switch (prop_id) {
	case PROP_NETWORK_STATE_CONN:
	{
		network_state->conn = g_value_get_boxed(value);
		INFO("network_state(%p) set conn(%p)", network_state, network_state->conn);
		break;
	}

	case PROP_NETWORK_STATE_PATH:
	{
		if (network_state->path)
			g_free(network_state->path);

		network_state->path = g_value_dup_string(value);
		INFO("network_state(%p) path(%s)", network_state, network_state->path);

		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_network_state_init(NetconfigNetworkState *network_state)
{
	DBG("network_state initialize");

	network_state->conn = NULL;
	network_state->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_network_state_class_init(NetconfigNetworkStateClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	DBG("class initialize");

	object_class->get_property = __netconfig_network_state_gobject_get_property;
	object_class->set_property = __netconfig_network_state_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_NETWORK_STATE,
			&dbus_glib_netconfig_iface_network_state_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_NETWORK_STATE_CONN,
			g_param_spec_boxed("conn", "CONNECTION", "DBus connection",
					DBUS_TYPE_G_CONNECTION,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property(object_class, PROP_NETWORK_STATE_PATH,
			g_param_spec_string("path", "Path", "Object path",
					PROP_DEFAULT_STR,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}


static void __netconfig_pop_3g_alert_syspoppup(void)
{
	int rv = 0;
	bundle *b = NULL;
	int wifi_ug_state = 0;

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &wifi_ug_state);
	if (wifi_ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND)
		return;

	b = bundle_create();

	bundle_add(b, "_SYSPOPUP_TITLE_", "Cellular connection popup");
	bundle_add(b, "_SYSPOPUP_TYPE_", "notification");
	bundle_add(b, "_SYSPOPUP_CONTENT_", "connected");

	DBG("Launch 3G alert network popup");
	rv = syspopup_launch("net-popup", b);

	bundle_free(b);
}

gboolean netconfig_iface_network_state_update_default_connection_info(
		NetconfigNetworkState *master,
		gchar *connection_type, gchar *connection_state,
		gchar *ip_addr, gchar *proxy_addr, GError **error)
{
	char *ip = NULL;
	char *proxy = NULL;
	int wifi_state = 0;
	int previous_network_status = 0;

	DBG("connection type (%s), connection state(%s), ip_addr(%s), proxy_addr(%s)",
			connection_type, connection_state, ip_addr, proxy_addr);

	if (netconfig_emulator_is_emulated() == TRUE)
		return FALSE;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_STATE, &wifi_state);
	vconf_get_int(VCONFKEY_NETWORK_STATUS, &previous_network_status);

	if (g_str_equal(connection_state, "idle") == TRUE &&
			previous_network_status != VCONFKEY_NETWORK_OFF) {
		vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_OFF);

		if (g_str_equal(connection_type, "wifi") == TRUE)
			if (wifi_state != VCONFKEY_NETWORK_WIFI_OFF)
				vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE,
						VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

		vconf_set_str(VCONFKEY_NETWORK_IP, "");
		vconf_set_str(VCONFKEY_NETWORK_PROXY, "");

		vconf_set_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 0);

		DBG("Successfully clear IP and PROXY up");
	} else if (g_str_equal(connection_state, "ready") == TRUE ||
			g_str_equal(connection_state, "online") == TRUE) {
		ip = vconf_get_str(VCONFKEY_NETWORK_IP);
		proxy = vconf_get_str(VCONFKEY_NETWORK_PROXY);

		DBG("existed ip (%s), proxy (%s)", ip, proxy);

		if (g_str_equal(connection_type, "wifi") == TRUE) {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_WIFI);

			if (wifi_state != VCONFKEY_NETWORK_WIFI_OFF)
				vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE,
						VCONFKEY_NETWORK_WIFI_CONNECTED);
		} else if (g_str_equal(connection_type, "cellular") == TRUE) {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_CELLULAR);

			if (wifi_state != VCONFKEY_NETWORK_WIFI_OFF)
				vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE,
						VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

			if (previous_network_status != VCONFKEY_NETWORK_CELLULAR)
				__netconfig_pop_3g_alert_syspoppup();
		}

		if (ip != NULL && ip_addr != NULL &&
				g_str_equal(ip, ip_addr) != TRUE)
			vconf_set_str(VCONFKEY_NETWORK_IP, ip_addr);

		if (proxy != NULL && proxy_addr != NULL &&
				g_str_equal(proxy, proxy_addr) != TRUE)
			vconf_set_str(VCONFKEY_NETWORK_PROXY, proxy_addr);

		vconf_set_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 1);

		DBG("Successfully update default network configuration");
	}

	return TRUE;
}

gpointer netconfig_network_state_create_and_init(DBusGConnection *conn)
{
	GObject *object;

	g_return_val_if_fail(conn != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_NETWORK_STATE, "conn", conn, "path",
			NETCONFIG_NETWORK_STATE_PATH, NULL);

	INFO("create network_state(%p)", object);

	dbus_g_connection_register_g_object(conn, NETCONFIG_NETWORK_STATE_PATH, object);

	INFO("network_state(%p) register DBus path(%s)", object, NETCONFIG_NETWORK_STATE_PATH);

	return object;
}
