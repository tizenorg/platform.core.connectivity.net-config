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

#ifndef __NETCONFIG_WIFI_AGENT_H__
#define  __NETCONFIG_WIFI_AGENT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

#define NETCONFIG_AGENT_FIELD_NAME "Name"
#define NETCONFIG_AGENT_FIELD_PASSPHRASE "Passphrase"
#define NETCONFIG_AGENT_FIELD_IDENTITY "Identity"

typedef struct {
	char *name;
	char *ssid;
	char *identity;
	char *passphrase;
	char *wpspin;
	char *username;
	char *password;
} NetconfigWifiAgentFields;

gboolean netconfig_agent_register(void);
gboolean netconfig_agent_unregister(void);
gboolean netconfig_iface_wifi_set_field(NetconfigWifi *wifi,
		GHashTable *fields, GError **error);
gboolean netconfig_iface_wifi_request_input(NetconfigWifi *wifi,
		gchar *service, GHashTable *fields,
		DBusGMethodInvocation *context);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_AGENT_H__ */
