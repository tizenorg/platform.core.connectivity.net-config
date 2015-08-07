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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <glib.h>
#include <unistd.h>

#include <vconf.h>

#include "log.h"
#include "util.h"
#include "neterror.h"
#include "wifi-config.h"

#define CONNMAN_STORAGE         "/var/lib/connman"
#define WIFI_CONFIG_PREFIX      "wifi_"

#define WIFI_CONFIG_NAME				"Name"
#define WIFI_CONFIG_SSID				"SSID"
#define WIFI_CONFIG_PASSPHRASE		"Passphrase"
#define WIFI_CONFIG_SECURITY_TYPE		"Security"
#define WIFI_CONFIG_FAVORITE			"Favorite"
#define WIFI_CONFIG_AUTOCONNECT		"AutoConnect"
#define WIFI_CONFIG_HIDDEN				"Hidden"
#define WIFI_CONFIG_FAILURE			"Failure"
#define WIFI_CONFIG_PROXYADDRESS		"ProxyAddress"
#define WIFI_CONFIG_PROXY_METHOD		"Proxy.Method"
#define WIFI_CONFIG_PROXY_SERVER		"Proxy.Servers"

#define WIFI_SECURITY_NONE		"none"
#define WIFI_SECURITY_WEP		"wep"
#define WIFI_SECURITY_WPA_PSK	"psk"
#define WIFI_SECURITY_EAP		"ieee8021x"

#define WIFI_PREFIX_LENGTH      18 // wifi_485a3f2f506a_

struct wifi_config {
	gchar *name;
	gchar *ssid;
	gchar *passphrase;
	gchar *security_type;
	gboolean favorite;
	gboolean autoconnect;
	gchar *is_hidden;
	gchar *proxy_address;
	gchar *last_error;
};

static gint __netconfig_get_mac_address(gchar **mac_address)
{
	gchar *tmp_mac = NULL;
	gchar *tmp = NULL;
	gchar mac[13] = { 0, };
	gint i = 0, j = 0;

	tmp_mac = vconf_get_str(VCONFKEY_WIFI_BSSID_ADDRESS);
	if (tmp_mac == NULL) {
		ERR("vconf_get_str(WIFI_BSSID_ADDRESS) Failed");
		*mac_address = NULL;
		return -1;
	}
	tmp = g_ascii_strdown(tmp_mac, (gssize)strlen(tmp_mac));
	g_free(tmp_mac);

	while (tmp[i]) {
		if (tmp[i] != ':') {
			mac[j++] = tmp[i];
		}
		i++;
	}
	mac[12] = '\0';
	*mac_address = g_strdup(mac);

	return 0;
}

static gboolean ___netconfig_remove_file(const gchar *pathname, const gchar *filename)
{
	gboolean ret = FALSE;
	gchar *path;

	path = g_strdup_printf("%s/%s", pathname, filename);
	if (g_file_test(path, G_FILE_TEST_EXISTS) == FALSE) {
		ret = TRUE;
	} else if (g_file_test(path, G_FILE_TEST_IS_REGULAR) == TRUE) {
		unlink(path);
		ret = TRUE;
	}

	g_free(path);
	return ret;
}

static gboolean __netconfig_remove_configuration(const gchar *pathname)
{
	int ret = 0;

	if (___netconfig_remove_file(pathname, "settings") != TRUE) {
		ERR("Cannot remove [%s/settings]", pathname);
		return FALSE;
	}
	if (___netconfig_remove_file(pathname, "data") != TRUE) {
		ERR("Cannot remove [%s/data]", pathname);
		return FALSE;
	}

	ret = rmdir(pathname);
	if (ret == -1) {
		ERR("Cannot remove [%s]", pathname);
		return FALSE;
	}

	return TRUE;
}

static gint _netconfig_get_security_type(const gchar *config_id, gchar **type)
{
	int ret = 0;

	if (g_str_has_suffix(config_id, WIFI_SECURITY_NONE) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_NONE);
	} else if (g_str_has_suffix(config_id, WIFI_SECURITY_WEP) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_WEP);
	} else if (g_str_has_suffix(config_id, WIFI_SECURITY_WPA_PSK) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_WPA_PSK);
	} else if (g_str_has_suffix(config_id, WIFI_SECURITY_EAP) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_EAP);
	} else {
		*type = NULL;
		ret = -1;
	}

	return ret;
}

static gboolean _netconfig_load_wifi_configuration(const gchar *config_id,
		struct wifi_config *config)
{
	GKeyFile *keyfile;
	gchar *path;
	gchar *group_name;
	gchar *mac_address = NULL;
	gboolean hidden = FALSE;

	__netconfig_get_mac_address(&mac_address);
	if (strlen(mac_address) == 0) {
		ERR("mac_address is NULL");
		return FALSE;
	}

	group_name = g_strdup_printf(WIFI_CONFIG_PREFIX "%s_%s", mac_address, config_id);
	g_free(mac_address);
	path = g_strdup_printf("/var/lib/connman/%s/settings", group_name);

	DBG("group_name %s", group_name);
	DBG("path %s", path);

	keyfile = netconfig_keyfile_load(path);
	if (keyfile == NULL) {
		ERR("keyfile[%s] is NULL", path);
		return FALSE;
	}
	config->name = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_NAME, NULL);
	config->passphrase = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_PASSPHRASE, NULL);
	_netconfig_get_security_type(config_id, &config->security_type);
	config->proxy_address = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_PROXY_SERVER, NULL);
	hidden = g_key_file_get_boolean(keyfile, group_name, WIFI_CONFIG_HIDDEN, NULL);
	if (hidden) {
		config->is_hidden = g_strdup("TRUE");
	} else {
		config->is_hidden = g_strdup("FALSE");
	}
	config->last_error = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_FAILURE, NULL);

	g_free(group_name);
	g_free(path);

	return TRUE;
}

static gboolean _netconfig_save_wifi_configuration(const gchar *config_id,
		const struct wifi_config *config)
{
	GKeyFile *keyfile;
	gchar *dir;
	gchar *path;
	gchar *group_name;
	gchar *mac_address = NULL;

	__netconfig_get_mac_address(&mac_address);
	if (mac_address == NULL) {
		ERR("mac_address is NULL");
		return FALSE;
	}

	group_name = g_strdup_printf("wifi_%s_%s", mac_address, config_id);
	g_free(mac_address);

	dir = g_strdup_printf(CONNMAN_STORAGE "/%s", group_name);
	if (g_file_test(dir, G_FILE_TEST_IS_DIR) == TRUE) {
		if (__netconfig_remove_configuration(dir) != TRUE) {
			ERR("[%s] is existed, but cannot remove", dir);
			g_free(group_name);
			g_free(dir);
			return FALSE;
		}
	}

	if (mkdir(dir, (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) < 0) {
		ERR("Cannot mkdir %s", dir);
		g_free(group_name);
		g_free(dir);
		return FALSE;
	}

	keyfile = g_key_file_new();
	g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_NAME, config->name);
	g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_SSID, config->ssid);

	if (config->passphrase != NULL)
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PASSPHRASE, config->passphrase);

	g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_FAVORITE, config->favorite);
	g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_AUTOCONNECT, config->autoconnect);

	// Optional field
	if (config->proxy_address != NULL) {
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PROXY_METHOD, "manual");
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PROXY_SERVER, config->proxy_address);
	}

	if (config->is_hidden != NULL) {
		gboolean hidden = FALSE;
		if (g_strcmp0(config->is_hidden, "TRUE") == 0) {
			hidden = TRUE;
		}
		g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_HIDDEN, hidden);
	}

	path = g_strdup_printf(CONNMAN_STORAGE "/%s/settings", group_name);
	netconfig_keyfile_save(keyfile, path);
	g_free(group_name);
	g_free(dir);
	g_free(path);

	return TRUE;
}

static gboolean _netconfig_remove_wifi_configuration(const gchar *config_id)
{
	gboolean ret = FALSE;
	gchar *dir;
	gchar *group_name;
	gchar *mac_address = NULL;

	__netconfig_get_mac_address(&mac_address);
	if (mac_address == NULL) {
		ERR("mac_address is NULL");
		return FALSE;
	}

	group_name = g_strdup_printf("wifi_%s_%s", mac_address, config_id);
	g_free(mac_address);

	dir = g_strdup_printf(CONNMAN_STORAGE "/%s", group_name);
	if (g_file_test(dir, G_FILE_TEST_IS_DIR) == TRUE) {
		if (__netconfig_remove_configuration(dir) != TRUE) {
			ERR("[%s] is existed, but cannot remove", dir);
			ret = FALSE;
		}
		INFO("Success to remove [%s]", dir);
		ret = TRUE;
	} else {
		ERR("[%s] is not existed", dir);
		ret = FALSE;
	}

	g_free(group_name);
	g_free(dir);

	return ret;
}

static gboolean _netconfig_set_wifi_config_field(const gchar *config_id,
		const gchar *key, const gchar *value)
{
	gboolean ret = TRUE;
	GKeyFile *keyfile;
	gchar *path;
	gchar *group_name;
	gchar *mac_address = NULL;

	__netconfig_get_mac_address(&mac_address);
	if (strlen(mac_address) == 0) {
		ERR("mac_address is NULL");
		return FALSE;
	}

	group_name = g_strdup_printf(WIFI_CONFIG_PREFIX "%s_%s", mac_address, config_id);
	g_free(mac_address);
	path = g_strdup_printf("/var/lib/connman/%s/settings", group_name);

	DBG("group_name %s", group_name);
	DBG("path %s", path);

	keyfile = netconfig_keyfile_load(path);
	if (keyfile == NULL) {
		ERR("keyfile[%s] is NULL", path);
		return FALSE;
	}

	if (g_strcmp0(key, WIFI_CONFIG_PROXY_METHOD) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	}else if (g_strcmp0(key, WIFI_CONFIG_PROXY_SERVER) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_HIDDEN) == 0) {
		gboolean hidden = FALSE;
		if (g_strcmp0(value, "TRUE") == 0) {
			hidden = TRUE;
		}
		g_key_file_set_boolean(keyfile, group_name, key, hidden);
	} else {
		ERR("key[%s] is not supported", key);
		ret = FALSE;
	}

	netconfig_keyfile_save(keyfile, path);
	g_free(group_name);
	g_free(path);

	return ret;
}

static GSList *_netconfig_get_wifi_config_list(void)
{
	GSList *list = NULL;
	struct dirent *d;
	DIR *dir;

	dir = opendir(CONNMAN_STORAGE);
	if (dir == NULL) {
		ERR("Cannot open dir %s", CONNMAN_STORAGE);
		return NULL;
	}

	while ((d = readdir(dir))) {
		if (g_strcmp0(d->d_name, ".") == 0 ||
				g_strcmp0(d->d_name, "..") == 0 ||
				strncmp(d->d_name, WIFI_CONFIG_PREFIX, strlen(WIFI_CONFIG_PREFIX)) != 0) {
			continue;
		}
		gchar *config_id = g_strdup(d->d_name + WIFI_PREFIX_LENGTH);
		list = g_slist_append(list, g_strdup(config_id));
		g_free(config_id);
	}
	closedir(dir);

	return list;
}

gboolean handle_get_config_ids(Wifi *wifi, GDBusMethodInvocation *context)
{
	guint i = 0;
	GSList *config_ids = NULL;
	guint length;
	gchar **result = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);

	config_ids = _netconfig_get_wifi_config_list();
	if (config_ids == NULL) {
		netconfig_error_no_profile(context);
		ERR("Fail to get config list");
		return FALSE;
	}

	length = g_slist_length(config_ids);
	result = g_new0(gchar *, length + 1);
	for (i = 0; i < length; i++) {
		gchar *config_id = g_slist_nth_data(config_ids, i);
		result[i] = g_strdup(config_id);
	}

	config_ids = g_slist_nth(config_ids, 0);
	g_slist_free_full(config_ids, g_free);

	wifi_complete_get_config_ids(wifi, context, (const gchar * const*)result);
	return TRUE;
}

gboolean handle_load_configuration(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id)
{
	gboolean ret = FALSE;
	gchar *name = NULL, *passphrase = NULL, *security_type = NULL;
	gchar *proxy_address = NULL, *is_hidden = NULL, *last_error = NULL;
	struct wifi_config *conf = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);

	conf = g_new0(struct wifi_config, 1);

	ret = _netconfig_load_wifi_configuration(config_id, conf);
	if (ret != TRUE) {
		g_free(conf);
		ERR("No wifi configuration");
		netconfig_error_no_profile(context);
		return FALSE;
	}

	name = g_strdup(conf->name);
	passphrase = g_strdup(conf->passphrase);
	security_type = g_strdup(conf->security_type);
	is_hidden = g_strdup(conf->is_hidden);

	if (conf->proxy_address != NULL) {
		proxy_address = g_strdup(conf->proxy_address);
		g_free(conf->proxy_address);
	} else {
		proxy_address = g_strdup("NONE");
	}
	if (conf->last_error != NULL) {
		last_error = g_strdup(conf->last_error);
		g_free(conf->last_error);
	} else {
		last_error = g_strdup("ERROR_NONE");
	}

	g_free(conf->name);
	g_free(conf->passphrase);
	g_free(conf->security_type);
	g_free(conf->is_hidden);
	g_free(conf);

	wifi_complete_load_configuration (wifi, context, name,
			passphrase, security_type, proxy_address, is_hidden, last_error);

	return TRUE;
}

gboolean handle_save_configuration(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id, GVariant *configuration)
{
	gboolean ret = FALSE;
	struct wifi_config *conf = NULL;
	GVariantIter *iter;
	GVariant *value;
	gchar *field;

	if ((wifi == NULL) || (config_id == NULL) || (configuration == NULL)) {
		ERR("Invaliad parameter");
		netconfig_error_invalid_parameter(context);
		return FALSE;
	}

	conf = g_new0(struct wifi_config, 1);

	g_variant_get(configuration, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &field, &value)) {
		if (g_strcmp0(field, WIFI_CONFIG_NAME) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->name = g_strdup(g_variant_get_string(value, NULL));
				ERR("name [%s]", conf->name);
			} else {
				conf->name = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_SSID) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->ssid = g_strdup(g_variant_get_string(value, NULL));
				ERR("ssid [%s]", conf->ssid);
			} else {
				conf->ssid = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_PASSPHRASE) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->passphrase = g_strdup(g_variant_get_string(value, NULL));
				ERR("passphrase [%s]", conf->passphrase);
			} else {
				conf->passphrase = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_HIDDEN) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->is_hidden = g_strdup(g_variant_get_string(value, NULL));
				ERR("is_hidden [%s]", conf->is_hidden);
			} else {
				conf->is_hidden = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_PROXYADDRESS) == 0) {
			conf->proxy_address = g_strdup(g_variant_get_string(value, NULL));
			ERR("proxy_address [%s]", conf->proxy_address);
		} else {
			conf->proxy_address = NULL;
		}
	}
	conf->favorite = TRUE;
	conf->autoconnect = TRUE;
	ret = _netconfig_save_wifi_configuration(config_id, conf);

	g_free(conf->name);
	g_free(conf->ssid);
	g_free(conf->passphrase);
	g_free(conf->is_hidden);
	g_free(conf->proxy_address);
	g_free(conf);

	g_variant_iter_free(iter);

	if (ret == TRUE) {
		wifi_complete_save_configuration(wifi, context);
	} else {
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_INTERNAL, "FailSaveConfiguration");
	}

	return ret;
}

gboolean handle_remove_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id)
{
	gboolean ret = FALSE;

	if ((wifi == NULL) || (config_id == NULL)) {
		ERR("Invaliad parameter");
		netconfig_error_invalid_parameter(context);
		return FALSE;
	}

	ret = _netconfig_remove_wifi_configuration(config_id);
	if (ret != TRUE) {
		// no configuration or error
		ERR("No [%s] configuration", config_id);
		netconfig_error_no_profile(context);
		return FALSE;
	}

	wifi_complete_remove_configuration(wifi, context);
	return ret;
}

// config field key / value
/*
 * [wifi_macaddress_config_id]
 * Name=name (mandatory)
 * SSID=SSID (mandatory)
 * Frequency=2462 (X)
 * Favorite=true (X)
 * AutoConnect=true (Default true)
 * Modified=2015-03-20 (X)
 * IPv4.method=manual (O)
 * IPv4.DHCP.LastAddress=192.0.0.1 (X)
 * IPv6.method=auto (X)
 * IPv6.privacy=disabled (X)
 * IPv4.netmask_prefixlen=24 (X)
 * IPv4.local_address=192.0.0.1 (O)
 * IPv4.gateway=192.0.0.1 (O ? X ?)
 * Nameservers=192.168.43.22; (O)
 * Proxy.Method=manual (O)
 * Proxy.Servers=trst.com:8888; (O)
 */
gboolean handle_set_config_field(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id, const gchar *key, const gchar *value)
{
	gboolean ret = FALSE;
	gchar *keyfile_key = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);
	g_return_val_if_fail(config_id != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);

	DBG("Key[%s] Value[%d]", key, value);

	if (g_strcmp0(key, WIFI_CONFIG_PROXYADDRESS) == 0) {
		ret = _netconfig_set_wifi_config_field(config_id, WIFI_CONFIG_PROXY_METHOD, "manual");
		if (!ret) {
			ERR("Fail to [%s]set_wifi_config_field(%s/manual)", config_id, WIFI_CONFIG_PROXY_METHOD);
			netconfig_error_invalid_parameter(context);
			return FALSE;
		}
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_PROXY_SERVER);
	} else if (g_strcmp0(key, WIFI_CONFIG_HIDDEN) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_HIDDEN);
	} else {
		ERR("Not supported key[%s]", key);
		netconfig_error_invalid_parameter(context);
		return FALSE;
	}

	ret = _netconfig_set_wifi_config_field(config_id, keyfile_key, (const gchar *)value);
	if (!ret) {
		ERR("Fail to [%s]set_wifi_config_field(%s/%s)", config_id, key, value);
		ret = FALSE;
	}

	if (keyfile_key != NULL)
		g_free(keyfile_key);

	wifi_complete_set_config_field(wifi,context);
	return ret;
}
