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

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "neterror.h"
#include "netdbus.h"
#include "netsupplicant.h"
#include "network-state.h"
#include <vconf.h>
#include <vconf-keys.h>
#include <arpa/inet.h>
#include <log.h>
#include "util.h"
#include "neterror.h"
#include "wifi-tdls.h"
#include <glib.h>

char *peer_mac = NULL;
int is_connected = 0;

void __netconfig_wifi_notify_tdls_event(const char *sig_name, const char *peer_mac)
{
	GVariantBuilder *builder;
	GVariant *params;
	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", "peermac", g_variant_new_string(peer_mac));

	params = g_variant_new("(@a{sv})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	netconfig_dbus_emit_signal(NULL,
				NETCONFIG_WIFI_PATH,
				NETCONFIG_WIFI_INTERFACE,
				sig_name,
				params);

	INFO("Sent signal (%s) Peer Mac (%s)", sig_name, peer_mac);
}

static GVariant * __netconfig_wifi_tdls_send_dbus_str(const char* method, const char *str)
{
	GVariant *message = NULL;
	const char *if_path = NULL;
	GVariant *params = NULL;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		ERR("Fail to get wpa_supplicant DBus path");
		return NULL;
	}

	params = g_variant_new("(s)", str);
	INFO("[TizenMW-->WPAS] Sent Dbus Method :[%s],value[%s]", method, str);
	message = netconfig_invoke_dbus_method(SUPPLICANT_SERVICE,
			if_path, SUPPLICANT_INTERFACE ".Interface", method, params);

	INFO("TDLS Returned from Blocking method for Send DBUS Command");
	return message;
}

gboolean handle_tdls_disconnect(Wifi *wifi, GDBusMethodInvocation *context,
			gchar *peer_mac_Addr)
{
	DBG("[TizenMW-->WPAS]: TDLS Teardown Request: [%s]", peer_mac_Addr);

	if (!is_connected) {
		ERR(" No active TDLS Connection !!!");
	} else {
		GVariant *message = NULL;
		message = __netconfig_wifi_tdls_send_dbus_str("TDLSTeardown", (const char*)peer_mac_Addr);
		DBG("[TizenMW<--WPAS] TDLS DBUS Command sent successfully");
		g_variant_unref(message);
		is_connected = 0;
	}

	wifi_complete_tdls_disconnect(wifi, context, 1);
	return TRUE;
}

gboolean handle_tdls_connected_peer(Wifi *wifi, GDBusMethodInvocation *context)
{
	DBG("[TizenMW-->WPAS]: TDLS Connected Peer Request: ");

	GVariant *message = NULL;
	const gchar* reply_str = NULL;

	if (peer_mac == NULL) {
		INFO("TDLS: No Active Connection");
		wifi_complete_tdls_connected_peer(wifi, context, "00.00.00.00.00.00");
		return TRUE;
	}
	message = __netconfig_wifi_tdls_send_dbus_str("TDLSStatus", (const char*)peer_mac);
	if (message == NULL) {
		ERR(" TDLS : No active TDLS Link Setup !!!");
		wifi_complete_tdls_connected_peer(wifi, context, "00.00.00.00.00.00");
		return TRUE;
	}

	g_variant_get(message, "(&s)", &reply_str);
	INFO("TDLS reply: [%s]", reply_str);
	INFO("TDLS :peer_mac [%s]", peer_mac);

	if (g_strcmp0("connected", reply_str) != 0) {
		ERR("[TizenMW<--WPAS] TDLS Connection not available");
		wifi_complete_tdls_connected_peer(wifi, context, "00.00.00.00.00.00");
		g_variant_unref(message);
		return TRUE;
	}

	INFO("[TizenMW<--WPAS] TDLS Connection available, Peer Mac address %s", peer_mac);
	wifi_complete_tdls_connected_peer(wifi, context, peer_mac);

	g_variant_unref(message);
	return TRUE;
}

void netconfig_wifi_tlds_connected_event(GVariant *message)
{

	DBG("[TizenMW<--WPAS] WiFi TDLS Connected EVENT");
	if (is_connected == 1) {
		INFO("TDLS Peer already connected");
		g_free(peer_mac);
	}

	g_variant_get(message, "(s)", &peer_mac);
	INFO("Peer Mac Address: [%s]", peer_mac);

	is_connected = 1;
	__netconfig_wifi_notify_tdls_event("TDLSConnect", peer_mac);
}

void netconfig_wifi_tlds_disconnected_event(GVariant *message)
{
	DBG("[TizenMW<--WPAS]: WiFi TDLS Disconnected EVENT");
	const gchar *peer_mac_addr = NULL;

	g_variant_get(message, "(&s)", &peer_mac_addr);
	if (g_strcmp0(peer_mac, peer_mac_addr) == 0) {
		INFO("TDLS Peer Disconnected Mac Address: [%s]", peer_mac);
		is_connected = 0;
		__netconfig_wifi_notify_tdls_event("TDLSDisconnect", peer_mac);
	} else
		INFO("TDLS Peer Disconnected peer_mac(%s) != peer_mac_address(%s)", peer_mac, peer_mac_addr);
}
