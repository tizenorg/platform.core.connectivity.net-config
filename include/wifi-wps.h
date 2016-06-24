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

#ifndef __NETCONFIG_WIFI_WPS_H__
#define __NETCONFIG_WIFI_WPS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

/* WPS Errors */
#define WPS_CFG_NO_ERROR 0
#define WPS_CFG_MSG_TIMEOUT 16
#define WPS_EI_NO_ERROR 0
#define WPS_EI_OPERATION_FAILED 1

gboolean netconfig_wifi_is_wps_enabled(void);

void netconfig_wifi_wps_signal_scandone(void);
void netconfig_wifi_wps_signal_scanaborted(void);

gboolean handle_request_wps_scan(Wifi *wifi, GDBusMethodInvocation *context);
gboolean handle_request_wps_connect(Wifi *wifi, GDBusMethodInvocation *context, gchar *param);
gboolean handle_request_wps_cancel(Wifi *wifi, GDBusMethodInvocation *context);
void netconfig_wifi_notify_wps_completed(const char *ssid);
void netconfig_wifi_notify_wps_fail_event(int config_error, int error_indication);
void netconfig_wifi_notify_wps_credentials(const char *ssid, const char *wps_key);
gboolean netconfig_get_wps_field();

#if defined TIZEN_TV
gboolean netconfig_wifi_wps_connect();
#endif

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_WPS_H__ */
