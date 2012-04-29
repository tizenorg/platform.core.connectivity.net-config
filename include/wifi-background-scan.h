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

#ifndef __NETCONFIG_WIFIBACKGROUNDSCAN_H_
#define __NETCONFIG_WIFIBACKGROUNDSCAN_H_

#ifdef __cplusplus
extern "C" {
#endif

void netconfig_wifi_bgscan_start(void);
void netconfig_wifi_bgscan_stop(void);

gboolean netconfig_iface_wifi_set_bgscan(NetconfigWifi *wifi, guint scan_mode, GError **error);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFIBACKGROUNDSCAN_H_ */
