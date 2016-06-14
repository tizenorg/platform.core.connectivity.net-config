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

#include <stdio.h>
#include <unistd.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "wifi.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-eap.h"
#include "wifi-wps.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "wifi-agent.h"
#include "wifi-firmware.h"
#include "wifi-ssid-scan.h"
#include "wifi-passpoint.h"
#include "wifi-eap-config.h"
#include "wifi-background-scan.h"
#include "wifi-config.h"
#include "wifi-tdls.h"

#if defined TIZEN_WLAN_BOARD_SPRD
#define SPRD_CP2_FIRMWARE_PATH "/usr/bin/cp2-downloader"
static int is_wifi_firmware_downloaded = FALSE;
#endif

static Wifi *wifi_object = NULL;
static NetConnmanAgent *connman_agent_object = NULL;
static WifiFirmware *wififirmware_object = NULL;

Wifi *get_wifi_object(void){
	return wifi_object;
}

static gboolean handle_check_black_list(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *name, const gchar *security_type, const gchar *eap)
{
	ERR("Name (%s)", name);
	INFO("disable to check");
	wifi_complete_check_black_list(wifi, context, TRUE);
	return TRUE;
}

static void _set_wifi_mac_address(void)
{
	gchar *mac_addr = NULL;

	mac_addr = vconf_get_str(VCONFKEY_WIFI_BSSID_ADDRESS);
	if (mac_addr == NULL) {
		if (strlen(mac_addr) == 0)
			netconfig_set_mac_address_from_file();
		g_free(mac_addr);
	}
}

void __netconfig_wifi_connect_reply(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	GDBusConnection *conn = NULL;
	GError *error = NULL;

	DBG("WiFi Connection Reply");

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		ERR("WiFi Connection Error [%s]", error->message);
		g_error_free(error);
		if (netconfig_dbus_emit_signal(NULL, NETCONFIG_WIFI_PATH,
				NETCONFIG_WIFI_INTERFACE, "WiFiConnectFail",
				NULL) == FALSE)
			ERR("Failed to emit WiFiConnectFail signal");
		else
			DBG("Successfully sent WiFiConnectFail signal");
	} else
		DBG("WiFi Connection has been initiated successfully");

	netconfig_gdbus_pending_call_unref();
	return;
}

#if defined TIZEN_WLAN_BOARD_SPRD
int wifi_firmware_download(void)
{
	int rv = 0;
	const char *path = SPRD_CP2_FIRMWARE_PATH;
	char *const args[] = { SPRD_CP2_FIRMWARE_PATH, NULL };
	char *const envs[] = { NULL };

	if (!is_wifi_firmware_downloaded) {
		rv = netconfig_execute_file(path, args, envs);
		if (rv < 0) {
			DBG("wifi firmware download fails");
			return -EIO;
		}
		is_wifi_firmware_downloaded = TRUE;
		DBG("wifi firmware download successes");
	}

	return 0;
}
#endif

void wifi_object_create_and_init(void)
{
	DBG("Create wifi object.");
	GDBusInterfaceSkeleton *interface_wifi = NULL;
	GDBusInterfaceSkeleton *interface_connman_agent = NULL;
	GDBusInterfaceSkeleton *interface_wifi_firmware = NULL;
	GDBusConnection *connection = NULL;
	GDBusObjectManagerServer *server = netdbus_get_wifi_manager();
	if (server == NULL)
		return;

	connection = netdbus_get_connection();
	g_dbus_object_manager_server_set_connection(server, connection);

	/*Interface netconfig.wifi*/
	wifi_object = wifi_skeleton_new();
	interface_wifi = G_DBUS_INTERFACE_SKELETON(wifi_object);

	/* WIFI power */
	g_signal_connect(wifi_object, "handle-load-driver",
			G_CALLBACK(handle_load_driver), NULL);
	g_signal_connect(wifi_object, "handle-remove-driver",
			G_CALLBACK(handle_remove_driver), NULL);
	g_signal_connect(wifi_object, "handle-load-p2p-driver",
				G_CALLBACK(handle_load_p2p_driver), NULL);
	g_signal_connect(wifi_object, "handle-remove-p2p-driver",
			G_CALLBACK(handle_remove_p2p_driver), NULL);

	/* WIFI state */
	g_signal_connect(wifi_object, "handle-get-wifi-state",
			G_CALLBACK(handle_get_wifi_state), NULL);

	/* WIFI scan */
	g_signal_connect(wifi_object, "handle-request-specific-scan",
			G_CALLBACK(handle_request_specific_scan), NULL);
	g_signal_connect(wifi_object, "handle-request-wps-scan",
			G_CALLBACK(handle_request_wps_scan), NULL);

	/* WIFI direct */
	g_signal_connect(wifi_object, "handle-launch-direct",
			G_CALLBACK(handle_launch_direct), NULL);

	/* EAP config */
	g_signal_connect(wifi_object, "handle-create-eap-config",
			G_CALLBACK(handle_create_eap_config), NULL);
	g_signal_connect(wifi_object, "handle-delete-eap-config",
			G_CALLBACK(handle_delete_eap_config), NULL);

	/* WIFI configuration */
	g_signal_connect(wifi_object, "handle-save-configuration",
			G_CALLBACK(handle_save_configuration), NULL);
	g_signal_connect(wifi_object, "handle-remove-configuration",
			G_CALLBACK(handle_remove_configuration), NULL);
	g_signal_connect(wifi_object, "handle-get-config-ids",
			G_CALLBACK(handle_get_config_ids), NULL);
	g_signal_connect(wifi_object, "handle-load-configuration",
			G_CALLBACK(handle_load_configuration), NULL);
	g_signal_connect(wifi_object, "handle-set-config-field",
			G_CALLBACK(handle_set_config_field), NULL);
	g_signal_connect(wifi_object, "handle-get-config-passphrase",
			G_CALLBACK(handle_get_config_passphrase), NULL);
	/* WIFI EAP configuration */
	g_signal_connect(wifi_object, "handle-save-eap-configuration",
			G_CALLBACK(handle_save_eap_configuration), NULL);
	g_signal_connect(wifi_object, "handle-load-eap-configuration",
			G_CALLBACK(handle_load_eap_configuration), NULL);

	/* BG scan mode */
	g_signal_connect(wifi_object, "handle-set-bgscan",
			G_CALLBACK(handle_set_bgscan), NULL);
	g_signal_connect(wifi_object, "handle-resume-bgscan",
			G_CALLBACK(handle_resume_bgscan), NULL);
	g_signal_connect(wifi_object, "handle-pause-bgscan",
			G_CALLBACK(handle_pause_bgscan), NULL);

	/* Passpoint */
	g_signal_connect(wifi_object, "handle-set-passpoint",
				G_CALLBACK(handle_set_passpoint), NULL);
	g_signal_connect(wifi_object, "handle-get-passpoint",
					G_CALLBACK(handle_get_passpoint), NULL);

	/* EAP authentication */
	g_signal_connect(wifi_object, "handle-get-aka-auth",
				G_CALLBACK(handle_get_aka_auth), NULL);
	g_signal_connect(wifi_object, "handle-get-sim-auth",
				G_CALLBACK(handle_get_sim_auth), NULL);
	g_signal_connect(wifi_object, "handle-get-sim-imsi",
				G_CALLBACK(handle_get_sim_imsi), NULL);
	g_signal_connect(wifi_object, "handle-req-aka-auth",
			G_CALLBACK(handle_req_aka_auth), NULL);
	g_signal_connect(wifi_object, "handle-req-sim-auth",
			G_CALLBACK(handle_req_sim_auth), NULL);

	/* WIFI MDM blacklist */
	g_signal_connect(wifi_object, "handle-check-black-list",
			G_CALLBACK(handle_check_black_list), NULL);

	/* TDLS methods */
	g_signal_connect(wifi_object, "handle-tdls-disconnect",
			G_CALLBACK(handle_tdls_disconnect), NULL);
	g_signal_connect(wifi_object, "handle-tdls-connected-peer",
			G_CALLBACK(handle_tdls_connected_peer), NULL);

	if (!g_dbus_interface_skeleton_export(interface_wifi, connection,
			NETCONFIG_WIFI_PATH, NULL)) {
		ERR("Export WIFI_PATH for wifi failed");
	}

	/* Interface connman.Agent */
	connman_agent_object = net_connman_agent_skeleton_new();

	interface_connman_agent = G_DBUS_INTERFACE_SKELETON(connman_agent_object);
	g_signal_connect(connman_agent_object, "handle-report-error",
			G_CALLBACK(handle_report_error), NULL);
	g_signal_connect(connman_agent_object, "handle-request-browser",
			G_CALLBACK(handle_request_browser), NULL);
	g_signal_connect(connman_agent_object, "handle-request-input",
			G_CALLBACK(handle_request_input), NULL);
	g_signal_connect(connman_agent_object, "handle-set-field",
			G_CALLBACK(handle_set_field), NULL);

	if (!g_dbus_interface_skeleton_export(interface_connman_agent, connection,
			NETCONFIG_WIFI_PATH, NULL)) {
		ERR("Export WIFI_PATH for agent failed");
	}

	/*Interface netconfig.wifi.Firmware*/
	wififirmware_object = wifi_firmware_skeleton_new();

	interface_wifi_firmware = G_DBUS_INTERFACE_SKELETON(wififirmware_object);
	g_signal_connect(wififirmware_object, "handle-start",
			G_CALLBACK(handle_start), NULL);
	g_signal_connect(wififirmware_object, "handle-stop",
				G_CALLBACK(handle_stop), NULL);

	if (!g_dbus_interface_skeleton_export(interface_wifi_firmware, connection,
			NETCONFIG_WIFI_PATH, NULL)) {
		ERR("Export WIFI_PATH for firmware failed");
	}

	_set_wifi_mac_address();

	wifi_power_initialize();

	return;
}

void wifi_object_deinit(void)
{
	g_object_unref(wifi_object);
	g_object_unref(connman_agent_object);
	g_object_unref(wififirmware_object);

	wifi_power_deinitialize();
}
