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
#include "wifi-agent.h"
#include "wifi-firmware.h"
#include "wifi-ssid-scan.h"
#include "wifi-passpoint.h"
#include "wifi-eap-config.h"
#include "wifi-background-scan.h"
#include "wifi-config.h"

static Wifi *netconfigwifi = NULL;
static NetConnmanAgent *netconnmanagent = NULL;
static WifiFirmware *netconfigwififirmware = NULL;

Wifi *get_netconfig_wifi_object(void){
	return netconfigwifi;
}

static gboolean handle_check_black_list(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *name, const gchar *security_type, const gchar *eap)
{
	ERR("Name (%s)", name);
	INFO("disable to check");
	wifi_complete_check_black_list (wifi, context, TRUE);
	return TRUE;
}

void netconfig_wifi_create_and_init(void)
{
	DBG("Create wifi object.");
	GDBusInterfaceSkeleton *interface = NULL;
	GDBusConnection *connection;
	GDBusObjectManagerServer *server = netconfig_get_wifi_manager();
	if (server == NULL)
		return;

	connection = netconfig_gdbus_get_connection();
	g_dbus_object_manager_server_set_connection(server, connection);

	/*Interface*/
	netconfigwifi = wifi_skeleton_new();
	interface = G_DBUS_INTERFACE_SKELETON(netconfigwifi);

	// WIFI power
	g_signal_connect(netconfigwifi, "handle-load-driver",
			G_CALLBACK(handle_load_driver), NULL);
	g_signal_connect(netconfigwifi, "handle-remove-driver",
			G_CALLBACK(handle_remove_driver), NULL);
	g_signal_connect(netconfigwifi, "handle-load-p2p-driver",
				G_CALLBACK(handle_load_p2p_driver), NULL);
	g_signal_connect(netconfigwifi, "handle-remove-p2p-driver",
			G_CALLBACK(handle_remove_p2p_driver), NULL);

	// WIFI scan
	g_signal_connect(netconfigwifi, "handle-request-specific-scan",
			G_CALLBACK(handle_request_specific_scan), NULL);
	g_signal_connect(netconfigwifi, "handle-request-wps-scan",
			G_CALLBACK(handle_request_wps_scan), NULL);

	// WIFI direct
	g_signal_connect(netconfigwifi, "handle-launch-direct",
			G_CALLBACK(handle_launch_direct), NULL);

	// EAP config
	g_signal_connect(netconfigwifi, "handle-create-eap-config",
			G_CALLBACK(handle_create_eap_config), NULL);
	g_signal_connect(netconfigwifi, "handle-delete-eap-config",
			G_CALLBACK(handle_delete_eap_config), NULL);

	// WIFI configuration
	g_signal_connect(netconfigwifi, "handle-save-configuration",
			G_CALLBACK(handle_save_configuration), NULL);
	g_signal_connect(netconfigwifi, "handle-remove-configuration",
			G_CALLBACK(handle_remove_configuration), NULL);
	g_signal_connect(netconfigwifi, "handle-get-config-ids",
			G_CALLBACK(handle_get_config_ids), NULL);
	g_signal_connect(netconfigwifi, "handle-load-configuration",
			G_CALLBACK(handle_load_configuration), NULL);
	g_signal_connect(netconfigwifi, "handle-set-config-field",
			G_CALLBACK(handle_set_config_field), NULL);

	// BG scan mode
	g_signal_connect(netconfigwifi, "handle-set-bgscan",
			G_CALLBACK(handle_set_bgscan), NULL);
	g_signal_connect(netconfigwifi, "handle-resume-bgscan",
			G_CALLBACK(handle_resume_bgscan), NULL);
	g_signal_connect(netconfigwifi, "handle-pause-bgscan",
			G_CALLBACK(handle_pause_bgscan), NULL);

	// Passpoint
	g_signal_connect(netconfigwifi, "handle-set-passpoint",
				G_CALLBACK(handle_set_passpoint), NULL);
	g_signal_connect(netconfigwifi, "handle-get-passpoint",
					G_CALLBACK(handle_get_passpoint), NULL);

	// EAP authentication
	g_signal_connect(netconfigwifi, "handle-get-aka-auth",
				G_CALLBACK(handle_get_aka_auth), NULL);
	g_signal_connect(netconfigwifi, "handle-get-sim-auth",
				G_CALLBACK(handle_get_sim_auth), NULL);
	g_signal_connect(netconfigwifi, "handle-get-sim-imsi",
				G_CALLBACK(handle_get_sim_imsi), NULL);
	g_signal_connect(netconfigwifi, "handle-req-aka-auth",
			G_CALLBACK(handle_req_aka_auth), NULL);
	g_signal_connect(netconfigwifi, "handle-req-sim-auth",
			G_CALLBACK(handle_req_sim_auth), NULL);

	// WIFI MDM blacklist
	g_signal_connect(netconfigwifi, "handle-check-black-list",
			G_CALLBACK(handle_check_black_list), NULL);

	if (!g_dbus_interface_skeleton_export(interface, connection,
			NETCONFIG_WIFI_PATH, NULL)) {
		ERR("Export WIFI_PATH for wifi failed");
	}

	interface = NULL;

	/*Interface 2*/
	netconnmanagent = net_connman_agent_skeleton_new();

	interface = G_DBUS_INTERFACE_SKELETON(netconnmanagent);
	g_signal_connect(netconnmanagent, "handle-report-error",
			G_CALLBACK(handle_report_error), NULL);
	g_signal_connect(netconnmanagent, "handle-request-browser",
			G_CALLBACK(handle_request_browser), NULL);
	g_signal_connect(netconnmanagent, "handle-request-input",
			G_CALLBACK(handle_request_input), NULL);
	g_signal_connect(netconnmanagent, "handle-set-field",
			G_CALLBACK(handle_set_field), NULL);

	if (!g_dbus_interface_skeleton_export(interface, connection,
			NETCONFIG_WIFI_PATH, NULL)) {
		ERR("Export WIFI_PATH for agent failed");
	}

	interface = NULL;

	/*Interface 3*/
	netconfigwififirmware = wifi_firmware_skeleton_new();

	interface = G_DBUS_INTERFACE_SKELETON(netconfigwififirmware);
	g_signal_connect(netconfigwififirmware, "handle-start",
			G_CALLBACK(handle_start), NULL);
	g_signal_connect(netconfigwififirmware, "handle-stop",
				G_CALLBACK(handle_stop), NULL);

	if (!g_dbus_interface_skeleton_export(interface, connection,
			NETCONFIG_WIFI_PATH, NULL)) {
		ERR("Export WIFI_PATH for firmware failed");
	}

	netconfig_wifi_power_initialize();

	return;
}

