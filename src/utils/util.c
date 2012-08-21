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

#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <vconf.h>
#include <vconf-keys.h>
#include <wifi-direct.h>
#include <syspopup_caller.h>

#include "log.h"
#include "util.h"
#include "neterror.h"
#include "wifi-state.h"

void netconfig_start_timer_seconds(int secs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id)
{
	guint t_id = 0;

	INFO("Register timer with callback pointer (%p)", callback);

	if (callback == NULL) {
		ERR("callback function is NULL");
		return;
	}

	if ((timer_id != NULL && *timer_id != 0)) {
		ERR("timer already is registered");
		return;
	}

	t_id = g_timeout_add_seconds(secs, callback, user_data);

	if (t_id == 0) {
		ERR("Can't add timer");
		return;
	}

	if (timer_id != NULL)
		*timer_id = t_id;
}

void netconfig_start_timer(int msecs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id)
{
	guint t_id = 0;

	INFO("Register timer with callback pointer (%p)", callback);

	if (callback == NULL) {
		ERR("callback function is NULL");
		return;
	}

	if ((timer_id != NULL && *timer_id != 0)) {
		ERR("timer already is registered");
		return;
	}

	t_id = g_timeout_add(msecs, callback, user_data);

	if (t_id == 0) {
		ERR("Can't add timer");
		return;
	}

	if (timer_id != NULL)
		*timer_id = t_id;
}

void netconfig_stop_timer(guint *timer_id)
{
	if (timer_id == NULL) {
		ERR("timer is NULL");
		return;
	}

	if (*timer_id != 0) {
		g_source_remove(*timer_id);
		*timer_id = 0;
	}
}

static gboolean __netconfig_test_device_picker()
{
	char *favorite_wifi_service = NULL;

	favorite_wifi_service = netconfig_wifi_get_favorite_service();
	if (favorite_wifi_service != NULL) {
		g_free(favorite_wifi_service);
		return FALSE;
	}

	return TRUE;
}

static void __netconfig_pop_device_picker(void)
{
	int rv = 0;
	bundle *b = NULL;
	int wifi_ug_state = 0;

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &wifi_ug_state);
	if (wifi_ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND)
		return;

	b = bundle_create();

	DBG("Launch Wi-Fi device picker");
	rv = syspopup_launch("wifi-qs", b);

	bundle_free(b);
}

static gboolean __netconfig_wifi_try_device_picker(gpointer data)
{
	if (__netconfig_test_device_picker() == TRUE)
		__netconfig_pop_device_picker();

	return FALSE;
}

static guint __netconfig_wifi_device_picker_timer_id(gboolean is_set_method,
		guint timer_id)
{
	static guint netconfig_wifi_device_picker_service_timer = 0;

	if (is_set_method != TRUE)
		return netconfig_wifi_device_picker_service_timer;

	if (netconfig_wifi_device_picker_service_timer != timer_id)
		netconfig_wifi_device_picker_service_timer = timer_id;

	return netconfig_wifi_device_picker_service_timer;
}

static void __netconfig_wifi_device_picker_set_timer_id(guint timer_id)
{
	__netconfig_wifi_device_picker_timer_id(TRUE, timer_id);
}

static guint __netconfig_wifi_device_picker_get_timer_id(void)
{
	return __netconfig_wifi_device_picker_timer_id(FALSE, -1);
}

void netconfig_wifi_device_picker_service_start(void)
{
	int wifi_ug_state;
	const int NETCONFIG_WIFI_DEVICE_PICKER_INTERVAL = 700;
	guint timer_id = 0;

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &wifi_ug_state);
	if (wifi_ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND)
		return;

	DBG("Register device picker timer with %d milliseconds",
			NETCONFIG_WIFI_DEVICE_PICKER_INTERVAL);

	netconfig_start_timer(NETCONFIG_WIFI_DEVICE_PICKER_INTERVAL,
			__netconfig_wifi_try_device_picker, NULL, &timer_id);

	__netconfig_wifi_device_picker_set_timer_id(timer_id);
}

void netconfig_wifi_device_picker_service_stop(void)
{
	guint timer_id = 0;

	timer_id = __netconfig_wifi_device_picker_get_timer_id();
	if (timer_id == 0)
		return;

	DBG("Clear device picker timer with timer_id %d", timer_id);

	netconfig_stop_timer(&timer_id);

	__netconfig_wifi_device_picker_set_timer_id(timer_id);
}

gboolean netconfig_is_wifi_direct_on(void)
{
	int wifi_direct_state = 0;

	vconf_get_int(VCONFKEY_WIFI_DIRECT_STATE, &wifi_direct_state);

	DBG("Wi-Fi direct mode %d", wifi_direct_state);
	return (wifi_direct_state != 0) ? TRUE : FALSE;
}

gboolean netconfig_is_wifi_tethering_on(void)
{
	int wifi_tethering_state = 0;

	vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &wifi_tethering_state);

	DBG("Wi-Ti tethering mode %d", wifi_tethering_state);
	if (wifi_tethering_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI)
		return TRUE;

	return FALSE;
}

gboolean netconfig_execute_file(const char *file_path,
		char *const args[], char *const env[])
{
	pid_t pid = 0;
	int rv = 0;
	errno = 0;

	if (!(pid = fork())) {
		register unsigned int index = 0;
		INFO("pid(%d), ppid (%d)", getpid(), getppid());
		INFO("Inside child, exec (%s) command", file_path);

		index = 0;
		while (args[index] != NULL) {
			INFO(" %s", args[index]);
			index++;
		}

		errno = 0;
		if (execve(file_path, args, env) == -1) {
			DBG("Fail to execute command...(%s)",
					strerror(errno));
			return FALSE;
		}
	} else if (pid > 0) {
		if (waitpid(pid, &rv, 0) == -1) {
			DBG("wait pid (%u) rv (%d)", pid, rv);

			if (WIFEXITED(rv)) {
				DBG("exited, rv=%d", WEXITSTATUS(rv));
			} else if (WIFSIGNALED(rv)) {
				DBG("killed by signal %d", WTERMSIG(rv));
			} else if (WIFSTOPPED(rv)) {
				DBG("stopped by signal %d", WSTOPSIG(rv));
			} else if (WIFCONTINUED(rv)) {
				DBG("continued");
			}
		}
		return TRUE;
	}

	DBG("failed to fork()...(%s)", strerror(errno));
	return FALSE;
}

gboolean netconfig_iface_wifi_launch_direct(NetconfigWifi *wifi, GError **error)
{
	gboolean ret = TRUE;

	DBG("Launch Wi-Fi direct daemon");

	const char *path = "/usr/bin/wifi-direct-server.sh";
	char *const args[] = { "wifi-direct-server.sh", "start" };
	char *const env[] = { NULL };

	ret = netconfig_execute_file(path, args, env);

	if (ret != TRUE) {
		INFO("Failed to launch Wi-Fi direct daemon");

		netconfig_error_wifi_direct_failed(error);
	}

	return ret;
}
