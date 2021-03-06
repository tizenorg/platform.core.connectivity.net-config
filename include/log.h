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

#ifndef __NETCONFIG_LOG_H__
#define __NETCONFIG_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <dlog.h>
#include <stdio.h>
#include <string.h>

#define __LOG(level, format, arg...) \
	do { \
		char *ch = strrchr(__FILE__, '/'); \
		ch = ch ? ch + 1 : __FILE__; \
		SLOG(level, PACKAGE, "%s:%s() "format"\n", ch, __FUNCTION__, ## arg); \
	} while(0)

#define __PRT(level, format, arg...) \
	do { \
		char *ch = strrchr(__FILE__, '/'); \
		ch = ch ? ch + 1 : __FILE__; \
		fprintf(stderr, PACKAGE": %s:%s() "format"\n", ch, __FUNCTION__, ## arg); \
	} while(0)

#define DBG(format, arg...)		__LOG(LOG_DEBUG, format, ## arg)
#define INFO(format, arg...)	__LOG(LOG_INFO, format, ## arg)
#define WARN(format, arg...)	__LOG(LOG_WARN, format, ## arg)
#define ERR(format, arg...)		__LOG(LOG_ERROR, format, ## arg)

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_LOG_H__ */
