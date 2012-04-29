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

#ifndef __NETCONFIG_ERROR_H__
#define __NETCONFIG_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "glib.h"

G_BEGIN_DECLS

typedef enum {
	NETCONFIG_NO_ERROR				= 0x00,
	NETCONFIG_ERROR_INTERNAL 		= 0x01,
	NETCONFIG_ERROR_NO_SERVICE 		= 0x02,
	NETCONFIG_ERROR_TRASPORT 		= 0x03,
	NETCONFIG_ERROR_NO_PROFILE 		= 0x04,
	NETCONFIG_ERROR_WRONG_PROFILE 	= 0x05,
	NETCONFIG_ERROR_WIFI_DRIVER_FAILURE = 0x06,
	NETCONFIG_ERROR_SECURITY_RESTRICTED = 0x07,
	NETCONFIG_ERROR_MAX 			= 0x08,
} NETCONFIG_ERROR;

GQuark netconfig_error_quark(void);

#define	NETCONFIG_ERROR_QUARK	(netconfig_error_quark())

G_END_DECLS

#ifdef __cplusplus
}
#endif

void netconfig_error_wifi_driver_failed(GError **error);
void netconfig_error_security_restricted(GError **error);
void netconfig_error_wifi_direct_failed(GError **error);

#endif /* __NETCONFIG_ERROR_H__ */
