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

#include <stdio.h>
#include <unistd.h>

#include "wifi-agent.h"
#include "log.h"
#include "wifi.h"
#include "netdbus.h"

static NetconfigWifiAgentFields agent;

static void _netconfig_agent_clear_fields(void)
{
	DBG("_netconfig_agent_clear_fields");

	g_free(agent.passphrase);
	g_free(agent.name);
	g_free(agent.identity);
}

gboolean netconfig_agent_register(void)
{
	DBG("netconfig_agent_register");

	DBusMessage *reply = NULL;
	char param1[64] = "";
	char *param_array[] = {NULL, NULL};

	snprintf(param1, 64, "objpath:%s", NETCONFIG_WIFI_PATH);
	param_array[0] = param1;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"RegisterAgent", param_array);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

gboolean netconfig_agent_unregister(void)
{
	DBG("netconfig_agent_unregister");

	DBusMessage *reply = NULL;
	char param1[64] = "";
	char *param_array[] = {NULL, NULL};

	snprintf(param1, 64, "objpath:%s", NETCONFIG_WIFI_PATH);
	param_array[0] = param1;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"UnregisterAgent", param_array);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	/* Clearing the agent fields */
	_netconfig_agent_clear_fields();

	return TRUE;
}

gboolean netconfig_iface_wifi_set_field(NetconfigWifi *wifi,
		GHashTable *fields, GError **error)
{
	DBG("netconfig_iface_wifi_set_field");
	g_return_val_if_fail(wifi != NULL, FALSE);

	GHashTableIter iter;
	gpointer field, value;

	g_hash_table_iter_init(&iter, fields);
	while (g_hash_table_iter_next(&iter, &field, &value)) {
		DBG("Field - [%s]", field);
		if (!strcmp(field, NETCONFIG_AGENT_FIELD_PASSPHRASE)) {
			if (NULL != agent.passphrase) {
				g_free(agent.passphrase);
			}

			if (NULL != value) {
				agent.passphrase = g_strdup(value);
				DBG("Set the agent field[%s] - [%s]", field,
						agent.passphrase);
			}
		} else if (!strcmp(field, NETCONFIG_AGENT_FIELD_NAME)) {
			if (NULL != agent.name) {
				g_free(agent.name);
			}

			if (NULL != value) {
				agent.name = g_strdup(value);
				DBG("Set the agent field[%s] - [%s]",
						field, agent.name);
			}
		} else if (!strcmp(field, NETCONFIG_AGENT_FIELD_IDENTITY)) {
			if (NULL != agent.identity) {
				g_free(agent.identity);
			}

			if (NULL != value) {
				agent.identity = g_strdup(value);
				DBG("Set the agent field[%s] - [%s]",
						field, agent.identity);
			}
		}
	}

	return TRUE;
}

gboolean netconfig_iface_wifi_request_input(NetconfigWifi *wifi,
		gchar *service, GHashTable *fields,
		DBusGMethodInvocation *context)
{
	DBG("netconfig_iface_wifi_request_input");

	g_return_val_if_fail(wifi != NULL, FALSE);

	GHashTableIter iter;
	gpointer field, value;
	GHashTable *out_table = NULL;
	GValue *ret_value = NULL;

	if (NULL == service)
		return FALSE;

	DBG("Service - [%s]", service);

	out_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
			g_free);
	if (NULL == out_table)
		return FALSE;

	g_hash_table_iter_init(&iter, fields);
	while (g_hash_table_iter_next(&iter, &field, &value)) {
		DBG("Field - [%s]", field);
		if (!strcmp(field, NETCONFIG_AGENT_FIELD_PASSPHRASE)) {
			DBG("Adding the field-value in table");
			ret_value = g_slice_new0(GValue);
			g_value_init(ret_value, G_TYPE_STRING);
			g_value_set_string(ret_value, agent.passphrase);
			g_hash_table_insert(out_table, g_strdup(field),
					ret_value);
		} else if (!strcmp(field, NETCONFIG_AGENT_FIELD_NAME)) {
			DBG("Adding the field-value in table");
			ret_value = g_slice_new0(GValue);
			g_value_init(ret_value, G_TYPE_STRING);
			g_value_set_string(ret_value, agent.name);
			g_hash_table_insert(out_table, g_strdup(field),
					ret_value);
		} else if (!strcmp(field, NETCONFIG_AGENT_FIELD_IDENTITY)) {
			DBG("Adding the field-value in table");
			ret_value = g_slice_new0(GValue);
			g_value_init(ret_value, G_TYPE_STRING);
			g_value_set_string(ret_value, agent.identity);
			g_hash_table_insert(out_table, g_strdup(field),
					ret_value);
		}
	}

	dbus_g_method_return(context, out_table);

	return TRUE;
}
