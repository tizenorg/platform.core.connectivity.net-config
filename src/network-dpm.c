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

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-power.h"
#include "network-dpm.h"
#include "network-state.h"

#define NETCONFIG_SIGNAL_DPM_WIFI			"DPMWifi"
#define NETCONFIG_SIGNAL_DPM_WIFI_PROFILE	"DPMWifiProfile"

static int dpm_policy_wifi = 0;
static int dpm_policy_wifi_profile = 0;

static void __netconfig_dpm_notify_result(const char *sig_name, const char *key)
{
	gboolean reply;
	GVariant *params;
	GVariantBuilder *builder = NULL;
	GDBusConnection *connection = NULL;
	GError *error = NULL;
	const char *prop_key = "key";

	INFO("[Signal] %s %s", sig_name, key);

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("Failed to get GDBus Connection");
		return;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", prop_key, g_variant_new_string(key));
	params = g_variant_new("(@a{sv})", g_variant_builder_end(builder));

	g_variant_builder_unref(builder);

	reply = g_dbus_connection_emit_signal(connection,
			NULL,
			NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE,
			sig_name,
			params,
			&error);

	if (reply != TRUE) {
		if (error != NULL) {
			ERR("Failed to send signal [%s]", error->message);
			g_error_free(error);
		}
		return;
	}

	INFO("Sent signal (%s), key (%s)", sig_name, key);
	return;
}

void netconfig_dpm_init(void)
{
	INFO("DPM initialized");
	return;
}

void netconfig_dpm_deinit(void)
{
	INFO("DPM deinitialized");
	return;
}

int netconfig_dpm_update_from_wifi(void)
{
	INFO("DPM update from wifi [%d]", dpm_policy_wifi);

	if (!dpm_policy_wifi) {
		int wifi_state = 0;
		vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
		if (wifi_state != VCONFKEY_WIFI_OFF) {
			int err = wifi_power_off();
			if (err < 0) {
				if (err == -EINPROGRESS)
					ERR("wifi power off : InProgress");
				else if (err == -EALREADY)
					ERR("wifi power off : AlreadyExists");
				else if (err == -EPERM)
					ERR("wifi power off : PermissionDenied");
				else
					ERR("wifi power off : WifiDriverFailed");
			} else
				DBG("wifi power off : ErrorNone");

			netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_OFF_BY_AIRPLANE, 0);
			netconfig_send_restriction_to_net_popup("Wi-Fi unavailable",
					"toast_popup", "wifi");
		}
	}

	return dpm_policy_wifi;
}

int netconfig_dpm_update_from_wifi_profile(void)
{
	INFO("DPM update from wifi profile [%d]", dpm_policy_wifi_profile);
	return dpm_policy_wifi_profile;
}

gboolean handle_device_policy_wifi(
		Network *object,
		GDBusMethodInvocation *context,
		gint state)
{
	INFO("DPM device policy wifi changed : [%d -> %d]",
		dpm_policy_wifi, state);

	dpm_policy_wifi = state;
	netconfig_dpm_update_from_wifi();
	__netconfig_dpm_notify_result(NETCONFIG_SIGNAL_DPM_WIFI,
		state ? "allowed" : "disallowed");

	network_complete_device_policy_wifi(object, context);
	return TRUE;
}

gboolean handle_device_policy_wifi_profile(
		Network *object,
		GDBusMethodInvocation *context,
		gint state)
{
	INFO("DPM device policy wifi profile changed : [%d -> %d]",
		dpm_policy_wifi_profile, state);

	dpm_policy_wifi_profile = state;
	netconfig_dpm_update_from_wifi_profile();
	__netconfig_dpm_notify_result(NETCONFIG_SIGNAL_DPM_WIFI_PROFILE,
		state ? "allowed" : "disallowed");

	network_complete_device_policy_wifi_profile(object, context);
	return TRUE;
}

