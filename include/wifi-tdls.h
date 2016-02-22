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
#ifndef __TIZEN_NETWORK_WIFI_TDLS_H__
#define __TIZEN_NETWORK_WIFI_TDLS_H__

#ifdef __cplusplus
	 extern "C" {
#endif

#include <glib.h>
#include "netsupplicant.h"

void netconfig_wifi_tlds_connected_event(GVariant *message);
void netconfig_wifi_tlds_disconnected_event(GVariant *message);
void __netconfig_wifi_notify_tdls_connected_event(const char *peer_mac);
gboolean handle_tdls_disconnect(Wifi *wifi, GDBusMethodInvocation *context, gchar *peer_mac_addr);
gboolean handle_tdls_connected_peer(Wifi *wifi, GDBusMethodInvocation *context);


#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_NETWORK_WIFI_TDLS_H__ */

