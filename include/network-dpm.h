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

#ifndef __NETCONFIG_NETWORK_DPM_H__
#define __NETCONFIG_NETWORK_DPM_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DPM_POLICY_WIFI				"wifi"
#define DPM_POLICY_WIFI_PROFILE		"wifi-profile-change"

void netconfig_dpm_init(void);
void netconfig_dpm_deinit(void);
void netconfig_dpm_get_restriction_policy(void);
int netconfig_dpm_is_enable_restriction_policy(const char *name);


#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETWORK_CLOCK_H__ */
