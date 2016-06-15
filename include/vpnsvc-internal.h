/*
 * Network Configuration - VPN Service Internal Module
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


#ifndef __NETCONFIG_VPN_SERVICE_INTERNAL_H__
#define __NETCONFIG_VPN_SERVICE_INTERNAL_H__

#include <vpn_service.h>

typedef struct _vpnsvc_tun_s {
	GDBusConnection *connection;            /**< D-Bus Connection */
	int fd;                                 /**< tun socket fd */
	int index;                              /**< tun index (if.iface_index) */
	char name[VPNSVC_VPN_IFACE_NAME_LEN];      /**< tun name (if.iface_name) */
	char session[VPNSVC_SESSION_STRING_LEN];/**< session name (user setting) */
	unsigned int mtu;                       /**< mtu (user setting) */
} vpnsvc_tun_s;

int vpn_service_init(const char* iface_name, size_t iface_name_len, int fd, vpnsvc_tun_s *handle_s);
int vpn_service_deinit(const char* dev_name);
int vpn_service_protect(int socket, const char* dev_name);
int vpn_service_up(int iface_index, const char* local_ip, const char* remote_ip,
						char* routes[], int prefix[], size_t nr_routes,
						char** dns_servers, size_t nr_dns, size_t total_dns_string_cnt,
						const char* dns_suffix, const unsigned int mtu);
int vpn_service_down(int iface_index);
int vpn_service_block_networks(char* nets_vpn[], int prefix_vpn[], size_t nr_nets_vpn,
		char* nets_orig[], int prefix_orig[], size_t nr_nets_orig);
int vpn_service_unblock_networks(void);

#endif /* __NETCONFIG_VPN_SERVICE_INTERNAL_H__ */

