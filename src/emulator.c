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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "emulator.h"

static gboolean netconfig_is_emulated = FALSE;

static gboolean __netconfig_emulator_test_emulation_env(void)
{
	/* TODO: this module contains exact keyword of Emulator virtual CPU.
	 *       It will be revised with emulator "uname" system information.
	 */
	const char CPUINFO[] = "/proc/cpuinfo";
	const char EMUL_VIRTUAL_CPU[] = "QEMU Virtual CPU";
	const int BUF_LEN_MAX = 255;
	char buf[BUF_LEN_MAX];
	char *model_name = NULL;
	gboolean ret = FALSE;
	FILE* fp = NULL;

	DBG("Test emulation environment");

	if ((fp = fopen(CPUINFO, "r")) == NULL) {
		ERR("Failed to open %s", CPUINFO);
		return FALSE;
	}

	while (fgets(buf, BUF_LEN_MAX, fp)) {
		if (g_ascii_strncasecmp(buf, "model name", 10) != 0)
			continue;

		model_name = g_strstr_len(buf, BUF_LEN_MAX-1, EMUL_VIRTUAL_CPU);

		if (model_name != NULL)
			ret = TRUE;

		break;
	}

	fclose(fp);

	return ret;
}

static void __netconfig_emulator_set_ip(void)
{
	const int BUF_LEN_MAX = 255;
	const char EMUL_IFNAME[] = "eth0";
	char ip[BUF_LEN_MAX];
	int sockfd = 0;
	struct ifreq ifr;

	if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		ERR("Failed to open socket");
		return;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	g_strlcpy((char*)&ifr.ifr_name, EMUL_IFNAME, sizeof(EMUL_IFNAME));

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		ERR("Error getting IP address");

		close(sockfd);
		return;
	}

	g_strlcpy(ip, (char*)inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), BUF_LEN_MAX);

	vconf_set_str(VCONFKEY_NETWORK_IP, ip);

	close(sockfd);
}

static void __netconfig_emulator_set_proxy(void)
{
	const char HTTP_PROXY[] = "http_proxy";
	char *proxy = NULL;

	proxy = getenv(HTTP_PROXY);
	DBG("Get system proxy: %s", proxy);

	if(proxy != NULL)
		vconf_set_str(VCONFKEY_NETWORK_PROXY, proxy);
}

static void __netconfig_emulator_set_network_state(void)
{
	vconf_set_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 1);
	vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_CELLULAR);
	vconf_set_int(VCONFKEY_DNET_STATE, VCONFKEY_DNET_NORMAL_CONNECTED);
}

static void __netconfig_emulator_config_emul_env(void)
{
	__netconfig_emulator_set_ip();
	__netconfig_emulator_set_proxy();
	__netconfig_emulator_set_network_state();
}

gboolean netconfig_emulator_is_emulated(void)
{
	return netconfig_is_emulated;
}

void netconfig_emulator_test_and_start(void)
{
	netconfig_is_emulated = __netconfig_emulator_test_emulation_env();

	DBG("Emulation environment tested: %s", netconfig_is_emulated ? "It's emulated" : "Not emulated");

	if (netconfig_is_emulated == TRUE)
		__netconfig_emulator_config_emul_env();
}
