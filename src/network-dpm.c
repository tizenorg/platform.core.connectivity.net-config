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

#include <dpm/restriction.h>
#include <dpm/wifi.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "wifi-power.h"
#include "network-dpm.h"

static dpm_context_h context = NULL;
static dpm_restriction_policy_h restriction_policy = NULL;
static dpm_wifi_policy_h wifi_policy = NULL;

static int dp_wifi_id = 0;
static int dp_wifi_profile_id = 0;
static int is_enable_wifi = 1;
static int is_enable_wifi_profile = 1;

static bool __dpm_policy_state_check(const char *state)
{
	if (!strcmp(state, "allowed"))
		return true;			
	else if (!strcmp(state, "disallowed"))
		return false;

	return false;
}

static void _dpm_policy_changed_cb(const char *name,
	const char *state, void *user_data)
{
	DBG("dpm wifi policy state changed : %s, %s", name, state);
	if (!strcmp(name, DPM_POLICY_WIFI)) {
		is_enable_wifi = __dpm_policy_state_check(state);
		DBG("dpm wifi policy state changed : %s",
			is_enable_wifi > 0 ? "ON" : "OFF");
	} else if (!strcmp(name, DPM_POLICY_WIFI_PROFILE)) {
		is_enable_wifi_profile = __dpm_policy_state_check(state);
		DBG("dpm wifi profile policy state changed : %s",
			is_enable_wifi_profile > 0 ? "ON" : "OFF");
	}

	if (!is_enable_wifi) {
		int wifi_state = 0;
		vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
		if (wifi_state != VCONFKEY_WIFI_OFF) {
			wifi_power_off();
			netconfig_send_restriction_to_net_popup("Wi-Fi unavailable",
					"toast_popup", "Wi-Fi");
		}
	}
}

void netconfig_dpm_init(void)
{
	int rv = 0;
	context = dpm_context_create();
	if (!context) {
		ERR("Failed to create dpm context");
		return;
	}
	
	restriction_policy = dpm_context_acquire_restriction_policy(context);
	if (!restriction_policy) {
		ERR("Failed to get restriction policy handle");
		dpm_context_destroy(context);
		context = NULL;
		return;
	}

	wifi_policy = dpm_context_acquire_wifi_policy(context);
	if (!wifi_policy) {
		ERR("Failed to get wifi policy handle");
		dpm_context_destroy(context);
		context = NULL;
		return;
	}

	rv = dpm_context_add_policy_changed_cb(context,
		DPM_POLICY_WIFI, _dpm_policy_changed_cb, NULL, &dp_wifi_id);
	if (rv != DPM_ERROR_NONE)
		ERR("Failed to register dpm wifi callback");

	rv = dpm_context_add_policy_changed_cb(context,
		DPM_POLICY_WIFI_PROFILE, _dpm_policy_changed_cb,
		NULL, &dp_wifi_profile_id);
	if (rv != DPM_ERROR_NONE)
		ERR("Failed to register dpm wifi profile callback");

	INFO("DPM initialized");
	return;
}

void netconfig_dpm_deinit(void)
{
	INFO("netconfig_dpm_deinit is called");

	if (context) {
		if (dp_wifi_id)
			dpm_context_remove_policy_changed_cb(context, dp_wifi_id);

		if (dp_wifi_profile_id)
			dpm_context_remove_policy_changed_cb(context, dp_wifi_profile_id);

		if (restriction_policy) {
			dpm_context_release_restriction_policy(context, restriction_policy);
			restriction_policy = NULL;
		}

		if (wifi_policy) {
			dpm_context_release_wifi_policy(context, wifi_policy);
			wifi_policy = NULL;
		}

		dpm_context_destroy(context);
		context = NULL;
	}

	netconfig_dpm_get_restriction_policy();

	INFO("DPM deinitialized");
	return;
}

void netconfig_dpm_get_restriction_policy(void)
{
	int rv = 0;

	rv = dpm_restriction_get_wifi_state(restriction_policy, &is_enable_wifi);
	if (rv != DPM_ERROR_NONE)
		ERR("Failed to get dpm restriction wifi state");

	rv = dpm_wifi_is_profile_change_restricted(wifi_policy, &is_enable_wifi_profile);
	if (rv != DPM_ERROR_NONE)
		ERR("Failed to get dpm restriction wifi profile state");

	return;
}

int netconfig_dpm_is_enable_restriction_policy(const char *name)
{
	if (!strcmp(name, DPM_POLICY_WIFI))
		return is_enable_wifi;
	else if (!strcmp(name, DPM_POLICY_WIFI_PROFILE))
		return is_enable_wifi_profile;

	return 0;
}
