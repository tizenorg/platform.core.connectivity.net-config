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

#ifndef __NETCONFIG_WIFI_SSID_SCAN_H__
#define __NETCONFIG_WIFI_SSID_SCAN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

gboolean netconfig_wifi_get_ssid_scan_state(void);

void netconfig_wifi_notify_ssid_scan_done(void);
void netconfig_wifi_bss_added(GVariant *message);

gboolean netconfig_wifi_ssid_scan(const char *ssid);

gboolean handle_request_specific_scan(Wifi *wifi,
		GDBusMethodInvocation *context, const gchar *ssid);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_SSID_SCAN_H__ */
