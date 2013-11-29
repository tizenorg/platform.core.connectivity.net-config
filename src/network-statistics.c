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

#include <vconf.h>
#include <vconf-keys.h>

#include "wifi.h"
#include "log.h"
#include "util.h"
#include "netsupplicant.h"
#include "wifi-indicator.h"
#include "network-statistics.h"

#include "netconfig-iface-network-statistics-glue.h"

#define NETCONFIG_NETWORK_STATISTICS_PATH	"/net/netconfig/network_statistics"

#define NETCONFIG_PROCDEVFILE		"/proc/net/dev"

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL

enum {
	PROP_O,
	PROP_NETWORK_STATISTICS_CONN,
	PROP_NETWORK_STATISTICS_PATH,
};

struct NetconfigNetworkStatisticsClass {
	GObjectClass parent;
};

struct NetconfigNetworkStatistics {
	GObject parent;

	DBusGConnection *conn;
	gchar *path;
};

G_DEFINE_TYPE(NetconfigNetworkStatistics, netconfig_network_statistics, G_TYPE_OBJECT);

static void __netconfig_network_statistics_gobject_get_property(GObject *object,
		guint prop_id, GValue *value, GParamSpec *pspec)
{
	return;
}

static void __netconfig_network_statistics_gobject_set_property(GObject *object,
		guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NetconfigNetworkStatistics *network_statistics = NETCONFIG_NETWORK_STATISTICS(object);

	switch (prop_id) {
	case PROP_NETWORK_STATISTICS_CONN:
	{
		network_statistics->conn = g_value_get_boxed(value);
		INFO("network_statistics(%p) set conn(%p)", network_statistics, network_statistics->conn);
		break;
	}

	case PROP_NETWORK_STATISTICS_PATH:
	{
		if (network_statistics->path)
			g_free(network_statistics->path);

		network_statistics->path = g_value_dup_string(value);
		INFO("network_statistics(%p) path(%s)", network_statistics, network_statistics->path);

		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_network_statistics_init(NetconfigNetworkStatistics *network_statistics)
{
	DBG("network_statistics initialize");

	network_statistics->conn = NULL;
	network_statistics->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_network_statistics_class_init(NetconfigNetworkStatisticsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	DBG("class initialize");

	object_class->get_property = __netconfig_network_statistics_gobject_get_property;
	object_class->set_property = __netconfig_network_statistics_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_NETWORK_STATISTICS,
			&dbus_glib_netconfig_iface_network_statistics_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_NETWORK_STATISTICS_CONN,
			g_param_spec_boxed("conn", "CONNECTION", "DBus connection",
					DBUS_TYPE_G_CONNECTION,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property(object_class, PROP_NETWORK_STATISTICS_PATH,
			g_param_spec_string("path", "Path", "Object path",
					PROP_DEFAULT_STR,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}


gboolean netconfig_wifi_get_bytes_statistics(guint64 *tx, guint64 *rx)
{
	gboolean ret = FALSE;
	FILE *fp;
	gchar buf[1024];
	gchar ifname[16] = { 0, };
	gchar *p_ifname = NULL, *p_entry = NULL;
	gchar *ifname_ptr = &ifname[0];

	*tx = 0;
	*rx = 0;

	if (netconfig_wifi_get_ifname(&ifname_ptr) != TRUE) {
		DBG("Fail to get Wi-Fi ifname from wpa_supplicant: %s", ifname_ptr);
		return FALSE;
	}

	fp = fopen(NETCONFIG_PROCDEVFILE, "r");
	if (fp == NULL) {
		ERR("Failed to open file %s", NETCONFIG_PROCDEVFILE);
		return FALSE;
	}

	/* skip the first and second line */
	if (fgets(buf, sizeof(buf), fp) == NULL ||
			fgets(buf, sizeof(buf), fp) == NULL)
		goto endline;

	while (fgets(buf, sizeof(buf), fp)) {
		guint64 llval;
		gulong lval;

		p_ifname = buf;
		while (*p_ifname == ' ') p_ifname++;
		p_entry = strchr(p_ifname, ':');
		*p_entry++ = '\0';

		if (g_str_equal(p_ifname, ifname) != TRUE)
			continue;

		/* read interface statistics */
		sscanf(p_entry,
				"%llu %llu %lu %lu %lu %lu %lu %lu "
				"%llu %llu %lu %lu %lu %lu %lu %lu",
				rx,			/* rx bytes */
				&llval,		/* rx packet */
				&lval,		/* rx errors */
				&lval,		/* rx dropped */
				&lval,		/* rx fifo errors */
				&lval,		/* rx frame errors */
				&lval,		/* rx compressed */
				&lval,		/* rx multicast */

				tx,			/* tx bytes */
				&llval,		/* tx packet */
				&lval,		/* tx errors */
				&lval,		/* tx dropped */
				&lval,		/* tx fifo errors */
				&lval,		/* collisions */
				&lval,		/* tx carrier errors */
				&lval		/* tx compressed */
				);

		ret = TRUE;
		break;
	}

endline:
	fclose(fp);
	return ret;
}

gboolean netconfig_iface_network_statistics_get_wifi_total_tx_bytes(NetconfigNetworkStatistics *network_statistics, guint64 *total_bytes, GError **error)
{
	guint64 tx = 0, rx = 0;
	guint64 tx_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, &val);
	tx_bytes = (guint64)val;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		*total_bytes = (guint64)tx + (guint64)tx_bytes;
	else
		*total_bytes = (guint64)tx_bytes;

	return TRUE;
}

gboolean netconfig_iface_network_statistics_get_wifi_total_rx_bytes(NetconfigNetworkStatistics *network_statistics, guint64 *total_bytes, GError **error)
{
	guint64 tx = 0, rx = 0;
	guint64 rx_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, &val);
	rx_bytes = (guint64)val;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		*total_bytes = (guint64)rx + (guint64)rx_bytes;
	else
		*total_bytes = (guint64)rx_bytes;

	return TRUE;
}

gboolean netconfig_iface_network_statistics_get_wifi_last_tx_bytes(NetconfigNetworkStatistics *network_statistics, guint64 *last_bytes, GError **error)
{
	guint64 tx = 0, rx = 0;
	guint64 tx_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, &val);
	tx_bytes = (guint64)val;

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		*last_bytes = (guint64)tx_bytes;
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		*last_bytes = (((guint64)tx - (guint64)tx_bytes) > (guint64)0) ?
				((guint64)tx - (guint64)tx_bytes) : (guint64)0;
	else
		*last_bytes = (guint64)tx_bytes;

	return TRUE;
}

gboolean netconfig_iface_network_statistics_get_wifi_last_rx_bytes(NetconfigNetworkStatistics *network_statistics, guint64 *last_bytes, GError **error)
{
	guint64 tx = 0, rx = 0;
	guint64 rx_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, &val);
	rx_bytes = (guint64)val;

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		*last_bytes = (guint64)rx_bytes;
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		*last_bytes = (((guint64)rx - (guint64)rx_bytes) > (guint64)0) ?
				((guint64)rx - (guint64)rx_bytes) : (guint64)0;
	else
		*last_bytes = (guint64)rx_bytes;

	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_cellular_total_tx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	vconf_set_int(VCONFKEY_NETWORK_CELLULAR_PKT_TOTAL_SNT, 0);
	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_cellular_total_rx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	vconf_set_int(VCONFKEY_NETWORK_CELLULAR_PKT_TOTAL_RCV, 0);
	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_cellular_last_tx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	vconf_set_int(VCONFKEY_NETWORK_CELLULAR_PKT_LAST_SNT, 0);
	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_cellular_last_rx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	vconf_set_int(VCONFKEY_NETWORK_CELLULAR_PKT_LAST_RCV, 0);
	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_wifi_total_tx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	guint64 tx = 0, rx = 0;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, -(int)tx);
	else
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, 0);

	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_wifi_total_rx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	guint64 tx = 0, rx = 0;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, -(int)rx);
	else
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, 0);

	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_wifi_last_tx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	guint64 tx = 0, rx = 0;

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, 0);
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, (int)tx);
	else
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, 0);

	return TRUE;
}

gboolean netconfig_iface_network_statistics_reset_wifi_last_rx_bytes(NetconfigNetworkStatistics *network_statistics, GError **error)
{
	guint64 tx = 0, rx = 0;

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, 0);
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, (int)rx);
	else
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, 0);

	return TRUE;
}

void netconfig_wifi_statistics_update_powered_off(void)
{
	guint64 cur_tx = 0, cur_rx = 0;
	guint64 prev_tx = 0, prev_rx = 0;
	guint64 total_tx = 0, total_rx = 0;
	int val = 0;

	if (netconfig_wifi_get_bytes_statistics(&cur_tx, &cur_rx) != TRUE)
		return;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, &val);
	prev_tx = (guint64)val;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, &val);
	prev_rx = (guint64)val;

	total_tx = prev_tx + cur_tx;
	total_rx = prev_rx + cur_rx;

	vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, (int)total_tx);
	vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, (int)total_rx);
}

static void netconfig_wifi_statistics_update_state(
		enum netconfig_wifi_service_state state, void *user_data)
{
	guint64 tx = 0, rx = 0;
	guint64 last_tx = 0, last_rx = 0;
	int val = 0;
	static enum netconfig_wifi_service_state prev_state = NETCONFIG_WIFI_UNKNOWN;

	if (prev_state == NETCONFIG_WIFI_UNKNOWN) {
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, 0);
		vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, 0);

		prev_state = NETCONFIG_WIFI_IDLE;
		return;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) != TRUE)
		return;

	if (state == NETCONFIG_WIFI_CONNECTED) {
		last_tx = tx;
		last_rx = rx;
	} else {
		if (prev_state != NETCONFIG_WIFI_CONNECTED)
			return;

		vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, &val);
		last_tx = (guint64)val;

		vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, &val);
		last_rx = (guint64)val;

		last_tx = (((guint64)tx - (guint64)last_tx) > (guint64)0) ?
				((guint64)tx - (guint64)last_tx) : (guint64)0;
		last_rx = (((guint64)rx - (guint64)last_rx) > (guint64)0) ?
				((guint64)rx - (guint64)last_rx) : (guint64)0;
	}

	vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, (int)last_tx);
	vconf_set_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, (int)last_rx);

	prev_state = state;
}

static struct netconfig_wifi_state_notifier state_notifier = {
		.netconfig_wifi_state_changed = netconfig_wifi_statistics_update_state,
		.user_data = NULL,
};

gpointer netconfig_network_statistics_create_and_init(DBusGConnection *conn)
{
	GObject *object;

	g_return_val_if_fail(conn != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_NETWORK_STATISTICS, "conn", conn, "path",
			NETCONFIG_NETWORK_STATISTICS_PATH, NULL);

	INFO("create network_statistics(%p)", object);

	dbus_g_connection_register_g_object(conn, NETCONFIG_NETWORK_STATISTICS_PATH, object);

	INFO("network_statistics(%p) register DBus path(%s)", object, NETCONFIG_NETWORK_STATISTICS_PATH);

	netconfig_wifi_statistics_update_state(NETCONFIG_WIFI_IDLE, NULL);
	netconfig_wifi_state_notifier_register(&state_notifier);

	return object;
}
