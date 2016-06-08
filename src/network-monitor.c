/*
 * Network Configuration Module
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "network-monitor.h"
#include "network-state.h"
#include "wifi-power.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <vconf.h>
#include <vconf-keys.h>

#define ETHERNET_CABLE_STATUS	"/sys/class/net/eth0/carrier"

/* Check send notification status */
static gboolean g_chk_eth_send_notification = FALSE;

int netconfig_ethernet_cable_plugin_status_check()
{
	int ret = -1;
	FILE *fd = NULL;
	char error_buf[MAX_SIZE_ERROR_BUFFER] = {0, };
	if(0 == access(ETHERNET_CABLE_STATUS, F_OK)) {
		fd = fopen(ETHERNET_CABLE_STATUS, "r");
		if(fd == NULL) {
			ERR("Error! Could not open /sys/class/net/eth0/carrier file\n");
			return -1;
		}
	} else {
		ERR("Error! Could not access /sys/class/net/eth0/carrier file\n");
		return -1;
	}

	int rv = 0;
	errno = 0;
	rv = fscanf(fd, "%d", &ret);
	if(rv < 0) {
		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		ERR("Error! Failed to read from file, rv:[%d], error:[%s]", rv, error_buf);
		fclose(fd);
		return -1;
	}

	if(ret == 1) {
		if(!g_chk_eth_send_notification) {
			ERR("/sys/class/net/eth0/carrier : [%d]", ret);
			netconfig_network_notify_ethernet_cable_state("ATTACHED");
		}
		g_chk_eth_send_notification = TRUE;
	} else if (ret == 0) {
		if(g_chk_eth_send_notification) {
			ERR("/sys/class/net/eth0/carrier : [%d]", ret);
			netconfig_network_notify_ethernet_cable_state("DETACHED");
		}
		g_chk_eth_send_notification = FALSE;
	}

	fclose(fd);
	return 0;
}

int netconfig_get_ethernet_cable_state(int *status)
{
	int error = 0;
	if (status == NULL) {
		DBG("Error !!! Invalid Parameter\n");
		return -1;
	}

	if ((error = netconfig_ethernet_cable_plugin_status_check()) != 0) {
		DBG("Error !!! Failed to check ethernet cable status [%d]\n", error);
		return -1;
	}

	if (g_chk_eth_send_notification == TRUE)
		*status = 1;		/* Ethernet cable Attached */
	else
		*status = 0;		/* Ethernet cable Deattached */
	return 0;
}
