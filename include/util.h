/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Danny JS Seo <S.Seo@samsung.com>
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

#ifndef __NETCONFIG_UTIL_H_
#define __NETCONFIG_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

#include "wifi.h"

void netconfig_start_timer_seconds(int secs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id);
void netconfig_start_timer(int msecs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id);
void netconfig_stop_timer(guint *timer_id);

void netconfig_wifi_device_picker_service_start(void);
void netconfig_wifi_device_picker_service_stop(void);

gboolean netconfig_is_wifi_direct_on(void);
gboolean netconfig_is_wifi_tethering_on(void);

void netconfig_wifi_check_local_bssid(void);
gboolean netconfig_execute_file(const char *file_path,
		char *const args[], char *const env[]);

gboolean netconfig_iface_wifi_launch_direct(NetconfigWifi *wifi, GError **error);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_UTIL_H_ */
