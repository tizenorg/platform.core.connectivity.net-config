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

#ifndef __NETCONFIG_NETDBUS_H__
#define __NETCONFIG_NETDBUS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#define CONNMAN_SERVICE					"net.connman"
#define CONNMAN_PATH					"/net/connman"

#define CONNMAN_MANAGER_INTERFACE		CONNMAN_SERVICE ".Manager"
#define CONNMAN_SERVICE_INTERFACE		CONNMAN_SERVICE ".Service"
#define CONNMAN_TECHNOLOGY_INTERFACE	CONNMAN_SERVICE ".Technology"
#define CONNMAN_MANAGER_PATH			"/"

#define CONNMAN_WIFI_SERVICE_PROFILE_PREFIX		CONNMAN_PATH "/service/wifi_"
#define CONNMAN_WIFI_TECHNOLOGY_PREFIX			CONNMAN_PATH "/technology/wifi"

#define NETCONFIG_WIFI_INTERFACE		"net.netconfig.wifi"
#define NETCONFIG_WIFI_PATH				"/net/netconfig/wifi"

#define DBUS_PATH_MAX_BUFLEN		512
#define DBUS_STATE_MAX_BUFLEN		64

typedef enum {
	NETCONFIG_DBUS_RESULT_GET_BGSCAN_MODE,
	NETCONFIG_DBUS_RESULT_DEFAULT_TECHNOLOGY,
} netconfig_dbus_result_type;

char *netconfig_wifi_get_connected_service_name(DBusMessage *message);
DBusMessage *netconfig_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, char *param_array[]);
void netconfig_dbus_parse_recursive(DBusMessageIter *iter,
		netconfig_dbus_result_type result_type, void *data);
char *netconfig_dbus_get_string(DBusMessage *msg);

DBusGConnection *netconfig_setup_dbus(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETDBUS_H__ */
