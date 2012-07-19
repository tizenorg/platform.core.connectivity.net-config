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

#include <glib.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "dbus.h"
#include "util.h"
#include "wifi.h"
#include "wifi-state.h"
#include "wifi-background-scan.h"

#define SCAN_PERIODIC_DELAY		10
#define SCAN_EXPONENTIAL_MIN	4
#define SCAN_EXPONENTIAL_MAX	128

enum {
	WIFI_BGSCAN_MODE_EXPONENTIAL = 0x00,
	WIFI_BGSCAN_MODE_PERIODIC,
	WIFI_BGSCAN_MODE_MAX,
};

struct bgscan_timer_data {
	guint time;
	guint mode;
	guint timer_id;
};

static struct bgscan_timer_data *__netconfig_wifi_bgscan_get_bgscan_data(void)
{
	static struct bgscan_timer_data timer_data = {SCAN_EXPONENTIAL_MIN, WIFI_BGSCAN_MODE_EXPONENTIAL, 0};

	return &timer_data;
}

static guint __netconfig_wifi_bgscan_mode(gboolean is_set_mode, guint mode)
{
	static guint bgscan_mode = WIFI_BGSCAN_MODE_EXPONENTIAL;

	if (is_set_mode != TRUE)
		return bgscan_mode;

	if (mode < WIFI_BGSCAN_MODE_MAX && mode >= WIFI_BGSCAN_MODE_EXPONENTIAL)
		bgscan_mode = mode;

	DBG("Wi-Fi background scan mode set %d", bgscan_mode);

	return bgscan_mode;
}

static void __netconfig_wifi_bgscan_set_mode(guint mode)
{
	__netconfig_wifi_bgscan_mode(TRUE, mode);
}

static guint __netconfig_wifi_bgscan_get_mode(void)
{
	return __netconfig_wifi_bgscan_mode(FALSE, -1);
}

static gboolean __netconfig_wifi_bgscan_request_connman_scan(void)
{
	DBusMessage *reply = NULL;
	/** dbus-send --system --print-reply --dest=net.connman / net.connman.Manager.SetProperty string:ScanMode variant:uint16:0/1/2/3 */
	char request[] = CONNMAN_MANAGER_INTERFACE ".RequestScan";
	char param1[] = "string:wifi";
	char path[] = CONNMAN_MANAGER_PATH;
	char *param_array[] = {
		NULL,
		NULL,
		NULL,
		NULL
	};

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTED)
		if (__netconfig_wifi_bgscan_get_mode() == WIFI_BGSCAN_MODE_EXPONENTIAL)
				return FALSE;

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTING)
		return FALSE;

	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = param1;

	DBG("Requesting [%s %s %s]", param_array[0], param_array[1], param_array[2]);

	reply = netconfig_dbus_send_request(CONNMAN_SERVICE, param_array);
	if (reply == NULL) {
		ERR("Error! Request failed");

		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static gboolean __netconfig_wifi_bgscan_request_scan(gpointer data);

static void __netconfig_wifi_bgscan_start_timer(struct bgscan_timer_data *data)
{
	if (data == NULL)
		return;

	netconfig_stop_timer(&(data->timer_id));

	data->mode = __netconfig_wifi_bgscan_get_mode();

	switch (data->mode) {
	case WIFI_BGSCAN_MODE_EXPONENTIAL:
		if (data->time == 0)
			data->time = SCAN_EXPONENTIAL_MIN;
		else if ((data->time >= SCAN_EXPONENTIAL_MAX) || (data->time > SCAN_EXPONENTIAL_MAX / 2))
			data->time = SCAN_EXPONENTIAL_MAX;
		else
			data->time = data->time * 2;

		DBG("Wi-Fi background scan with exponentially increasing period");
		break;

	case WIFI_BGSCAN_MODE_PERIODIC:
		data->time = SCAN_PERIODIC_DELAY;

		DBG("Wi-Fi background scan periodically");
		break;

	default:
		DBG("Error! Wi-Fi background scan mode [%d]", data->mode);
		return;
	}

	DBG("Register background scan timer with %d seconds", data->time);

	netconfig_start_timer_seconds(data->time, __netconfig_wifi_bgscan_request_scan, data, &(data->timer_id));
}

static void __netconfig_wifi_bgscan_stop_timer(struct bgscan_timer_data *data)
{
	if (data == NULL)
		return;

	DBG("Stop Wi-Fi background scan timer");

	netconfig_stop_timer(&(data->timer_id));
}

static gboolean __netconfig_wifi_bgscan_request_scan(gpointer data)
{
	struct bgscan_timer_data *timer = (struct bgscan_timer_data *)data;

	if (timer == NULL)
		return FALSE;

	DBG("Request Wi-Fi scan to ConnMan");

	__netconfig_wifi_bgscan_stop_timer(timer);

	__netconfig_wifi_bgscan_request_connman_scan();

	__netconfig_wifi_bgscan_start_timer(timer);

	return FALSE;
}

void netconfig_wifi_bgscan_start(void)
{
	struct bgscan_timer_data *timer_data = __netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data == NULL)
		return;

	DBG("Wi-Fi background scan start");

	__netconfig_wifi_bgscan_request_connman_scan();

	__netconfig_wifi_bgscan_start_timer(timer_data);
}

void netconfig_wifi_bgscan_stop(void)
{
	struct bgscan_timer_data *timer_data = __netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data == NULL)
		return;

	DBG("Wi-Fi background scan stop");

	timer_data->time = SCAN_EXPONENTIAL_MIN;

	__netconfig_wifi_bgscan_stop_timer(timer_data);
}

gboolean netconfig_iface_wifi_set_bgscan(NetconfigWifi *wifi, guint scan_mode, GError **error)
{
	struct bgscan_timer_data *timer_data = __netconfig_wifi_bgscan_get_bgscan_data();

	DBG("Wi-Fi background scan mode set: %d", scan_mode);

	if (scan_mode >= WIFI_BGSCAN_MODE_MAX || scan_mode < WIFI_BGSCAN_MODE_EXPONENTIAL)
		return FALSE;

	switch (scan_mode) {
		case WIFI_BGSCAN_MODE_PERIODIC:
			DBG("[%s]BG scan mode is periodic", __FUNCTION__);
			break;
		case WIFI_BGSCAN_MODE_EXPONENTIAL:
			DBG("[%s]BG scan mode is exponential", __FUNCTION__);
			break;
		default:
			DBG("[%s]strange value [%d]", __FUNCTION__, scan_mode);
			break;
	}

	__netconfig_wifi_bgscan_set_mode(scan_mode);

	if (timer_data->timer_id != 0) {
		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start();
	}

	return TRUE;
}
