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

#ifndef __NETCONFIG_WIFI_STATE_H__
#define __NETCONFIG_WIFI_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

enum netconfig_wifi_service_state {
	NETCONFIG_WIFI_UNKNOWN		= 0x00,
	NETCONFIG_WIFI_IDLE			= 0x01,
	NETCONFIG_WIFI_ASSOCIATION	= 0x02,
	NETCONFIG_WIFI_CONFIGURATION	= 0x03,
	NETCONFIG_WIFI_CONNECTED	= 0x04,
	NETCONFIG_WIFI_FAILURE		= 0x05,
};

enum netconfig_wifi_tech_state {
	NETCONFIG_WIFI_TECH_UNKNOWN			= 0x00,
	NETCONFIG_WIFI_TECH_OFF				= 0x01,
	NETCONFIG_WIFI_TECH_WPS_ONLY		= 0x02,
	NETCONFIG_WIFI_TECH_POWERED			= 0x03,
	NETCONFIG_WIFI_TECH_CONNECTED		= 0x04,
	NETCONFIG_WIFI_TECH_TETHERED		= 0x05,
};

struct netconfig_wifi_state_notifier {
	void (*netconfig_wifi_state_changed)
		(enum netconfig_wifi_service_state, void *user_data);
	void *user_data;
};

#define VCONF_WIFI_LAST_POWER_STATE "file/private/wifi/last_power_state"

void netconfig_wifi_set_bss_found(const gboolean found);
gboolean netconfig_wifi_is_bss_found(void);
void netconfig_wifi_state_set_service_state(
		enum netconfig_wifi_service_state new_state);
enum netconfig_wifi_service_state
		netconfig_wifi_state_get_service_state(void);

void netconfig_wifi_state_set_technology_state(
		enum netconfig_wifi_tech_state new_state);
enum netconfig_wifi_tech_state
	netconfig_wifi_state_get_technology_state(void);

void netconfig_wifi_notify_power_failed(void);
void netconfig_wifi_notify_power_completed(gboolean power_on);
void netconfig_wifi_update_power_state(gboolean powered);

char *netconfig_wifi_get_favorite_service(void);

void netconfig_wifi_start_timer_network_notification(void);

void netconfig_wifi_state_notifier_cleanup(void);
void netconfig_wifi_state_notifier_register(
		struct netconfig_wifi_state_notifier *notifier);
void netconfig_wifi_state_notifier_unregister(
		struct netconfig_wifi_state_notifier *notifier);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_STATE_H__ */
