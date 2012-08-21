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

#include <glib.h>

#include "neterror.h"
#include "netconfig.h"

#define NETCONFIG_ERROR_INTERFACE NETCONFIG_SERVICE ".Error"

GQuark netconfig_error_quark(void)
{
	static GQuark quark = 0;

	if (!quark)
		quark = g_quark_from_static_string("netconfig_error");

	return quark;
}

void netconfig_error_wifi_driver_failed(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_WIFI_DRIVER_FAILURE,
			NETCONFIG_ERROR_INTERFACE ".WifiDriverFailed");
}

void netconfig_error_security_restricted(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_SECURITY_RESTRICTED,
			NETCONFIG_ERROR_INTERFACE ".SecurityRestricted");
}

void netconfig_error_wifi_direct_failed(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_WIFI_DRIVER_FAILURE,
			NETCONFIG_ERROR_INTERFACE ".WifiDirectFailed");
}
