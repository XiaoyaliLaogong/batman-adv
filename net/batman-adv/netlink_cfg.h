/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2010-2018  B.A.T.M.A.N. contributors:
 *
 * Sven Eckelmann
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _NET_BATMAN_ADV_NETLINK_CFG_H_
#define _NET_BATMAN_ADV_NETLINK_CFG_H_

#include "main.h"

#include <linux/types.h>

struct genl_info;
struct netlink_callback;
struct netlink_ext_ack;
struct sk_buff;

#define __BATADV_PARAM_MAX_STRING_VALUE 32

/**
 * union batadv_config_value - variant storage for batadv_option
 */
union batadv_config_value {
	u8 vu8;
	u16 vu16;
	u32 vu32;
	unsigned int vbool:1;
	char string[__BATADV_PARAM_MAX_STRING_VALUE];
};

/**
 * struct batadv_option - configuration option data
 * @name: name of option
 * @type: netlink type of option
 * @get: get option value
 * @set: set option value
 * @validate: (optional) pre-validate input data
 */
struct batadv_option {
	const char *name;
	int type;
	int (*get)(struct batadv_priv *bat_priv, void *ext_arg,
		   union batadv_config_value *val);
	int (*set)(struct batadv_priv *bat_priv, void *ext_arg,
		   const union batadv_config_value *val);
	int (*validate)(struct batadv_priv *bat_priv, void *ext_arg,
			const union batadv_config_value *val,
			struct netlink_ext_ack *extack);
};

int batadv_get_option(struct sk_buff *skb, struct genl_info *info);
int batadv_set_option(struct sk_buff *skb, struct genl_info *info);
int batadv_get_option_dump(struct sk_buff *msg, struct netlink_callback *cb);

int batadv_get_option_hardif(struct sk_buff *skb, struct genl_info *info);
int batadv_set_option_hardif(struct sk_buff *skb, struct genl_info *info);
int batadv_get_option_hardif_dump(struct sk_buff *msg,
				  struct netlink_callback *cb);

int batadv_get_option_vlan(struct sk_buff *skb, struct genl_info *info);
int batadv_set_option_vlan(struct sk_buff *skb, struct genl_info *info);
int batadv_get_option_vlan_dump(struct sk_buff *msg,
				struct netlink_callback *cb);

#endif /* _NET_BATMAN_ADV_NETLINK_CFG_H_ */
