/*
 * Network Configuration - VPN Service Module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdlib.h>
#include <unistd.h>
#include <gio/gunixfdlist.h>

#include "vpnsvc.h"
#include "vpnsvc-internal.h"
#include "netdbus.h"
#include "log.h"

static Vpnsvc *vpnsvc = NULL;

/*********************
 * Handler Functions *
 ********************/
gboolean handle_vpn_init(Vpnsvc *object,
								GDBusMethodInvocation *invocation,
								const gchar *arg_iface_name,
								guint arg_iface_name_len)
{
	DBG("handle_vpn_init");

	int result = VPNSVC_ERROR_NONE;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE) == false
		|| vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_INTERNET) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	vpnsvc_tun_s handle_s;
	GDBusMessage *msg;
	GUnixFDList *fd_list;
	int fd_list_length;
	const int *fds;

	DBG("vpn_init, %s, %u\n", arg_iface_name, arg_iface_name_len);

	msg = g_dbus_method_invocation_get_message(invocation);
	fd_list = g_dbus_message_get_unix_fd_list(msg);
	fds = g_unix_fd_list_peek_fds(fd_list, &fd_list_length);

	if (fd_list_length <= 0)
		DBG("D-Bus Message doesn't contain any fd!");

	DBG("fd:%d\n", *fds);

	result = vpn_service_init(arg_iface_name, arg_iface_name_len, *fds, &handle_s);

	DBG("handle_s.fd : %d, handle_s.index : %d, handle_s.name : %s",
			handle_s.fd, handle_s.index, handle_s.name);

	vpnsvc_complete_vpn_init(object, invocation, result, handle_s.index, handle_s.name);

	return TRUE;
}

gboolean handle_vpn_deinit(Vpnsvc *object,
									GDBusMethodInvocation *invocation,
									const gchar *arg_dev_name)
{
	DBG("handle_vpn_deinit");

	int result = VPNSVC_ERROR_NONE;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE) == false
		|| vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_INTERNET) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	DBG("vpn_deinit, %s\n", arg_dev_name);

	result = vpn_service_deinit(arg_dev_name);

	vpnsvc_complete_vpn_deinit(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_protect(Vpnsvc *object,
									GDBusMethodInvocation *invocation,
									const gchar *arg_dev_name)
{
	DBG("handle_vpn_protect");

	int result = VPNSVC_ERROR_NONE;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE) == false
		|| vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_INTERNET) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	int socket;
	GDBusMessage *msg;
	GUnixFDList *fd_list;
	int fd_list_length;
	const int *fds;

	msg = g_dbus_method_invocation_get_message(invocation);
	fd_list = g_dbus_message_get_unix_fd_list(msg);
	fds = g_unix_fd_list_peek_fds(fd_list, &fd_list_length);
	if (fd_list_length <= 0)
		DBG("D-Bus Message doesn't contain any fd!");

	socket = *fds;
	DBG("vpn_protect, %d, %s\n", socket, arg_dev_name);

	result = vpn_service_protect(socket, arg_dev_name);

	vpnsvc_complete_vpn_protect(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_up(Vpnsvc *object,
								GDBusMethodInvocation *invocation,
								gint arg_iface_index,
								const gchar *arg_local_ip,
								const gchar *arg_remote_ip,
								GVariant *arg_routes,
								guint arg_nr_routes,
								GVariant *arg_dns_servers,
								guint arg_nr_dns,
								const gchar *arg_dns_suffix,
								guint arg_mtu)
{
	DBG("handle_vpn_up");

	int result = VPNSVC_ERROR_NONE;

	char *routes[arg_nr_routes];
	int prefix[arg_nr_routes];
	char **dns_servers = NULL;

	unsigned int i = 0;
	size_t total_dns_string_cnt = 0;
	gchar* temp_dns_server;
	GVariantIter iter;

	gchar* route_dest;
	gint route_prefix;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE_ADMIN) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	DBG("iface_index : %d", arg_iface_index);
	DBG("local ip : %s", arg_local_ip);
	DBG("remote ip : %s", arg_remote_ip);
	DBG("dns_suffix : %s", arg_dns_suffix);
	DBG("mtu : %u", arg_mtu);
	DBG("arg_routes: %p", arg_routes);
	DBG("nr_routes : %u", arg_nr_routes);
	DBG("arg_dns_servers: %p", arg_dns_servers);
	DBG("nr_dns : %u", arg_nr_dns);

	/* arg_routes check */
	if (arg_nr_routes > 0) {
		if (arg_routes != NULL) {
			GVariant *dict = g_variant_get_variant(arg_routes);
			g_variant_iter_init(&iter, dict);
			i = 0;
			while (g_variant_iter_loop(&iter, "{si}", &route_dest, &route_prefix)) {
				int temp_dest_str_len = strlen(route_dest);
				routes[i] = g_try_malloc0((sizeof(char) * temp_dest_str_len)+1);
				strncpy(routes[i], route_dest, temp_dest_str_len);
				routes[i][temp_dest_str_len] = '\0';
				prefix[i] = route_prefix;
				DBG("routes[%d] = %s \t", i, (routes[i] == NULL) ? "" : routes[i]);
				DBG("prefix[%d] = %d ", i, prefix[i]);
				i++;
			}
		}
	}


	/* arg_nr_dns check */
	if (arg_nr_dns > 0) {
		if (arg_dns_servers != NULL) {
			GVariant *array = g_variant_get_variant(arg_dns_servers);
			dns_servers = (char **)g_try_malloc0(arg_nr_dns*sizeof(char *));
			if (dns_servers == NULL) {
				ERR("malloc failed.");
				result = VPNSVC_ERROR_OUT_OF_MEMORY;
				goto done;
			}
			g_variant_iter_init(&iter, array);
			i = 0;
			while (g_variant_iter_loop(&iter, "s", &temp_dns_server)) {
				int temp_dns_str_len = strlen(temp_dns_server);
				dns_servers[i] = (char *)g_try_malloc0((temp_dns_str_len + 1) * sizeof(char));
				strncpy(dns_servers[i], temp_dns_server, strlen(temp_dns_server));
				dns_servers[i][temp_dns_str_len] = '\0';
				total_dns_string_cnt += temp_dns_str_len;
				DBG("dns_servers[%d] : %s", i, (dns_servers[i] == NULL) ? "" : dns_servers[i]);
				i++;
			}
		}
	}

	result = vpn_service_up(arg_iface_index, arg_local_ip, arg_remote_ip,
			routes, prefix, arg_nr_routes, dns_servers, arg_nr_dns,
			total_dns_string_cnt, arg_dns_suffix, arg_mtu);
done:
	/* free pointers */
	for (i = 0; i < arg_nr_routes; i++) {
		if (routes[i])
			g_free(routes[i]);
	}

	if (dns_servers) {
		for (i = 0; i < arg_nr_dns; i++) {
			if (dns_servers[i])
				g_free(dns_servers[i]);
		}
		g_free(dns_servers);
	}

	vpnsvc_complete_vpn_up(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_down(Vpnsvc *object,
									GDBusMethodInvocation *invocation,
									gint arg_iface_index)
{
	DBG("handle_vpn_down");

	int result = VPNSVC_ERROR_NONE;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE_ADMIN) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	DBG("vpn_down, %d\n", arg_iface_index);

	result = vpn_service_down(arg_iface_index);

	vpnsvc_complete_vpn_down(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_block_networks(Vpnsvc *object,
											GDBusMethodInvocation *invocation,
											GVariant *arg_nets_vpn,
											guint arg_nr_nets_vpn,
											GVariant *arg_nets_orig,
											guint arg_nr_nets_orig)
{
	DBG("handle_vpn_block_networks");

	int result = VPNSVC_ERROR_NONE;

	char *nets_vpn[arg_nr_nets_vpn];
	int prefix_vpn[arg_nr_nets_vpn];

	char *nets_orig[arg_nr_nets_vpn];
	int prefix_orig[arg_nr_nets_vpn];

	int i = 0;
	GVariantIter iter;
	gchar* route_dest;
	gint route_prefix;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE) == false
		|| vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_INTERNET) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	DBG("vpn_block_networks");

	/* arg_nets_vpn check */
	if (arg_nr_nets_vpn > 0) {
		if (arg_nets_vpn != NULL) {
			GVariant *dict_nets_vpn = g_variant_get_variant(arg_nets_vpn);
			g_variant_iter_init(&iter, dict_nets_vpn);
			i = 0;
			while (g_variant_iter_loop(&iter, "{si}", &route_dest, &route_prefix)) {
				int tmp_route_len = strlen(route_dest);
				nets_vpn[i] = g_try_malloc0(sizeof(char) * tmp_route_len + 1);
				strncpy(nets_vpn[i], route_dest, tmp_route_len);
				nets_vpn[i][tmp_route_len] = '\0';
				prefix_vpn[i] = route_prefix;
				DBG("nets_vpn[%d] = %s \t", i, (nets_vpn[i] == NULL) ? "" : nets_vpn[i]);
				DBG("prefix_vpn[%d] = %d ", i, prefix_vpn[i]);
				i++;
			}
		}
	}

	/* arg_nets_orig check */
	if (arg_nr_nets_orig > 0) {
		if (arg_nets_orig != NULL) {
			GVariant *dict_nets_orig = g_variant_get_variant(arg_nets_orig);
			g_variant_iter_init(&iter, dict_nets_orig);
			i = 0;
			while (g_variant_iter_loop(&iter, "{si}", &route_dest, &route_prefix)) {
				int tmp_route_len = strlen(route_dest);
				nets_orig[i] = g_try_malloc0(sizeof(char) * tmp_route_len + 1);
				strncpy(nets_orig[i], route_dest, tmp_route_len);
				nets_orig[i][tmp_route_len] = '\0';
				prefix_orig[i] = route_prefix;
				DBG("nets_orig[%d] = %s \t", i, (nets_orig[i] == NULL) ? "" : nets_orig[i]);
				DBG("prefix_orig[%d] = %d ", i, prefix_orig[i]);
				i++;
			}
		}
	}

	/* call function */
	result = vpn_service_block_networks(nets_vpn, prefix_vpn, arg_nr_nets_vpn, nets_orig, prefix_orig, arg_nr_nets_orig);

	for (i = 0; i < arg_nr_nets_vpn; ++i) {
		g_free(nets_orig[i]);
		g_free(nets_vpn[i]);
	}

	vpnsvc_complete_vpn_block_networks(object, invocation, result);

	return TRUE;
}

gboolean handle_vpn_unblock_networks(Vpnsvc *object,
											GDBusMethodInvocation *invocation)
{
	DBG("handle_vpn_unblock_networks");

	int result = VPNSVC_ERROR_NONE;

	/* check privilege */
	/*
	if (vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_VPN_SERVICE) == false
		|| vpnsvc_gdbus_check_privilege(invocation, PRIVILEGE_INTERNET) == false) {
		vpnsvc_error_permission_denied(invocation);
		return FALSE;
	}
	*/

	DBG("vpn_unblock_networks");

	result = vpn_service_unblock_networks();

	vpnsvc_complete_vpn_unblock_networks(object, invocation, result);

	return TRUE;
}

/*****************************
 * Initializations Functions *
 ****************************/
Vpnsvc *get_vpnsvc_object(void)
{
	return vpnsvc;
}

void vpnsvc_create_and_init(void)
{
	DBG("Create vpn object.");
	GDBusInterfaceSkeleton *interface_vpn = NULL;
	GDBusConnection *connection = NULL;
	GDBusObjectManagerServer *server = netdbus_get_vpn_manager();
	if (server == NULL)
		return;

	connection = netdbus_get_connection();
	g_dbus_object_manager_server_set_connection(server, connection);

	/* Interface */
	vpnsvc = vpnsvc_skeleton_new();
	interface_vpn = G_DBUS_INTERFACE_SKELETON(vpnsvc);

	/* VPN Service */
	g_signal_connect(vpnsvc, "handle-vpn-init",
			G_CALLBACK(handle_vpn_init), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-deinit",
			G_CALLBACK(handle_vpn_deinit), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-protect",
			G_CALLBACK(handle_vpn_protect), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-up",
			G_CALLBACK(handle_vpn_up), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-down",
			G_CALLBACK(handle_vpn_down), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-block-networks",
			G_CALLBACK(handle_vpn_block_networks), NULL);
	g_signal_connect(vpnsvc, "handle-vpn-unblock-networks",
			G_CALLBACK(handle_vpn_unblock_networks), NULL);

	if (!g_dbus_interface_skeleton_export(interface_vpn, connection,
			NETCONFIG_VPNSVC_PATH, NULL)) {
		ERR("Export NETCONFIG_VPNSVC_PATH for vpn failed");
	}

	return;
}

void vpnsvc_destroy_deinit(void)
{
	DBG("Deinit vpn object.");

	if (vpnsvc)
		g_object_unref(vpnsvc);
}

/*
gboolean vpnsvc_gdbus_check_privilege(GDBusMethodInvocation *invocation, net_vpn_service_privilege_e _privilege)
{

	int ret = 0;
	int pid = 0;
	char *user;
	char *client;
	char *client_session;
	char *privilege = NULL;
	cynara *p_cynara = NULL;
	const char *sender_unique_name;
	GDBusConnection *connection;

	connection = g_dbus_method_invocation_get_connection(invocation);
	sender_unique_name = g_dbus_method_invocation_get_sender(invocation);

	ret = cynara_initialize(&p_cynara, NULL);
	if (ret != CYNARA_API_SUCCESS) {
		DBG("cynara_initialize() failed");
		return FALSE;
	}

	ret = cynara_creds_gdbus_get_pid(connection, sender_unique_name, &pid);
	if (ret != CYNARA_API_SUCCESS) {
		DBG("cynara_creds_gdbus_get_pid() failed");
		return FALSE;
	}

	ret = cynara_creds_gdbus_get_user(connection, sender_unique_name, USER_METHOD_DEFAULT, &user);
	if (ret != CYNARA_API_SUCCESS) {
		DBG("cynara_creds_gdbus_get_user() failed");
		return FALSE;
	}

	ret = cynara_creds_gdbus_get_client(connection, sender_unique_name, CLIENT_METHOD_DEFAULT, &client);
	if (ret != CYNARA_API_SUCCESS) {
		DBG("cynara_creds_gdbus_get_client() failed");
		return FALSE;
	}

	switch (_privilege) {
	case PRIVILEGE_VPN_SERVICE:
		privilege = "http://tizen.org/privilege/vpnservice";
	break;

	case PRIVILEGE_VPN_SERVICE_ADMIN:
		privilege = "http://tizen.org/privilege/vpnservice.admin";
	break;

	case PRIVILEGE_INTERNET:
		privilege = "http://tizen.org/privilege/internet";
	break;
	default:
		DBG("Undifined privilege");
		return FALSE;
	break;
	}

	client_session = cynara_session_from_pid(pid);

	ret = cynara_check(p_cynara, client, client_session, user, privilege);
	if (ret == CYNARA_API_ACCESS_ALLOWED)
		DBG("cynara PASS");

	cynara_finish(p_cynara);

	g_free(client);
	g_free(user);
	g_free(client_session);

	return (ret == CYNARA_API_ACCESS_ALLOWED) ? TRUE : FALSE;
}
*/

