// SPDX-License-Identifier: GPL-2.0
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

#include "netlink_cfg.h"
#include "main.h"

#include <linux/errno.h>
#include <linux/genetlink.h>
#include <linux/gfp.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <uapi/linux/batadv_packet.h>
#include <uapi/linux/batman_adv.h>

#include "hard-interface.h"
#include "netlink.h"
#include "soft-interface.h"

static const struct batadv_option softif_options[] = {
};

static const struct batadv_option hardif_options[] = {
};

static const struct batadv_option vlan_options[] = {
};

/**
 * batadv_find_option() - Search for option with the correct name
 * @name: name of the option to find
 * @options: array of available options
 * @options_num: number of entries in @options
 *
 * Return: pointer to option on success or NULL in case of failure
 */
static const struct batadv_option *
batadv_find_option(const char *name, const struct batadv_option options[],
		   size_t options_num)
{
	size_t i;

	for (i = 0; i < options_num; i++) {
		if (strcmp(options[i].name, name) != 0)
			continue;

		return &options[i];
	}

	return NULL;
}

/**
 * batadv_option_value_get_from_info() - Validate and extract value from msg
 * @option: option to extract value for
 * @info: generic netlink info with attributes
 * @val: Target to save value
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_value_get_from_info(const struct batadv_option *option,
					     struct genl_info *info,
					     union batadv_config_value *val)
{
	struct nlattr *nla = info->attrs[BATADV_ATTR_OPTION_VALUE];
	int attrlen;
	int minlen;

	if (option->type != NLA_FLAG && !nla)
		return -EINVAL;

	switch (option->type) {
	case NLA_U8:
		attrlen = nla_len(nla);
		if (attrlen < sizeof(u8))
			return -EINVAL;

		val->vu8 = nla_get_u8(nla);
		break;
	case NLA_U16:
		attrlen = nla_len(nla);
		if (attrlen < sizeof(u16))
			return -EINVAL;

		val->vu16 = nla_get_u16(nla);
		break;
	case NLA_U32:
		attrlen = nla_len(nla);
		if (attrlen < sizeof(u32))
			return -EINVAL;

		val->vu32 = nla_get_u32(nla);
		break;
	case NLA_NUL_STRING:
		attrlen = nla_len(nla);
		minlen = min_t(int, __BATADV_PARAM_MAX_STRING_VALUE, attrlen);
		if (!minlen || !memchr(nla_data(nla), '\0', minlen))
			return -EINVAL;

		strlcpy(val->string, nla_data(nla), sizeof(val->string));
		break;
	case NLA_FLAG:
		val->vbool = !!nla;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * batadv_get_option_fill_open() - Fill message with option data and keep it
 *  open for further attributes
 * @msg: Netlink message to dump into
 * @hdr: storage position for header
 * @bat_priv: the bat priv with all the soft interface information
 * @option: option to dump
 * @ext_arg: Additional option argument
 * @cmd: type of message to generate
 * @portid: Port making netlink request
 * @seq: sequence number for message
 * @flags: Additional flags for message
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_get_option_fill_open(struct sk_buff *msg, void **hdr,
				       struct batadv_priv *bat_priv,
				       const struct batadv_option *option,
				       void *ext_arg,
				       enum batadv_nl_commands cmd,
				       u32 portid, u32 seq, int flags)
{
	union batadv_config_value val;
	int ret;

	ret = option->get(bat_priv, ext_arg, &val);
	if (ret < 0)
		return ret;

	*hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, flags,
			   cmd);
	if (!*hdr)
		return -EMSGSIZE;

	if (nla_put_string(msg, BATADV_ATTR_OPTION_NAME, option->name))
		return -EMSGSIZE;

	if (nla_put_u8(msg, BATADV_ATTR_OPTION_TYPE, option->type))
		return -EMSGSIZE;

	switch (option->type) {
	case NLA_U8:
		if (nla_put_u8(msg, BATADV_ATTR_OPTION_VALUE, val.vu8))
			return -EMSGSIZE;
		break;
	case NLA_U16:
		if (nla_put_u16(msg, BATADV_ATTR_OPTION_VALUE, val.vu16))
			return -EMSGSIZE;
		break;
	case NLA_U32:
		if (nla_put_u32(msg, BATADV_ATTR_OPTION_VALUE, val.vu32))
			return -EMSGSIZE;
		break;
	case NLA_NUL_STRING:
		if (nla_put_string(msg, BATADV_ATTR_OPTION_VALUE, val.string))
			return -EMSGSIZE;
		break;
	case NLA_FLAG:
		if (val.vbool && nla_put_flag(msg, BATADV_ATTR_OPTION_VALUE))
			return -EMSGSIZE;
		break;
	}

	return 0;
}

/**
 * batadv_get_option_fill() - Fill message with option data
 * @msg: Netlink message to dump into
 * @bat_priv: the bat priv with all the soft interface information
 * @option: option to dump
 * @ext_arg: Additional option argument
 * @cmd: type of message to generate
 * @portid: Port making netlink request
 * @seq: sequence number for message
 * @flags: Additional flags for message
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_get_option_fill(struct sk_buff *msg,
				  struct batadv_priv *bat_priv,
				  const struct batadv_option *option,
				  void *ext_arg, enum batadv_nl_commands cmd,
				  u32 portid, u32 seq, int flags)
{
	void *hdr;
	int ret;

	ret = batadv_get_option_fill_open(msg, &hdr, bat_priv, option, ext_arg,
					  cmd, portid, seq, flags);
	if (ret < 0)
		return ret;

	genlmsg_end(msg, hdr);
	return 0;
}

/**
 * batadv_option_notify() - send new option value to listener
 * @bat_priv: the bat priv with all the soft interface information
 * @option: option which was modified
 *
 * Return: 0 on success, < 0 on error
 */
static int batadv_option_notify(struct batadv_priv *bat_priv,
				const struct batadv_option *option)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = batadv_get_option_fill_open(msg, &hdr, bat_priv, option, NULL,
					  BATADV_CMD_SET_OPTION, 0, 0, 0);
	if (ret < 0)
		goto nla_put_failure;

	if (nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX,
			bat_priv->soft_iface->ifindex))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&batadv_netlink_family,
				dev_net(bat_priv->soft_iface), msg, 0,
				BATADV_NL_MCGRP_CONFIG, GFP_KERNEL);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	ret = -EMSGSIZE;
	nlmsg_free(msg);
	return ret;
}

/**
 * batadv_get_option() - Get softif option
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
int batadv_get_option(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	const struct batadv_option *option;
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;
	const char *option_name;
	struct sk_buff *msg;
	int ifindex;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_NAME])
		return -EINVAL;

	option_name = nla_data(info->attrs[BATADV_ATTR_OPTION_NAME]);
	option = batadv_find_option(option_name, softif_options,
				    ARRAY_SIZE(softif_options));
	if (!option)
		return -EOPNOTSUPP;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto err_put_softif;
	}

	ret = batadv_get_option_fill(msg, bat_priv, option,
				     NULL, BATADV_CMD_GET_OPTION,
				     info->snd_portid, info->snd_seq, 0);
	if (ret < 0) {
		nlmsg_free(msg);
		goto err_put_softif;
	}

	ret = genlmsg_reply(msg, info);

err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_set_option() - Set softif option
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
int batadv_set_option(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	const struct batadv_option *option;
	struct net_device *soft_iface;
	union batadv_config_value val;
	struct batadv_priv *bat_priv;
	const char *option_name;
	int option_type;
	int ifindex;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_NAME])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_TYPE])
		return -EINVAL;

	option_name = nla_data(info->attrs[BATADV_ATTR_OPTION_NAME]);
	option = batadv_find_option(option_name, softif_options,
				    ARRAY_SIZE(softif_options));
	if (!option)
		return -EOPNOTSUPP;

	option_type = nla_get_u8(info->attrs[BATADV_ATTR_OPTION_TYPE]);
	if (option_type != option->type)
		return -EINVAL;

	ret = batadv_option_value_get_from_info(option, info, &val);
	if (ret < 0)
		return ret;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	ret = option->set(bat_priv, NULL, &val);
	if (ret < 0)
		goto err_put_softif;

	batadv_option_notify(bat_priv, option);

err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_get_option_dump() - Dump softif options into a message
 * @msg: Netlink message to dump into
 * @cb: Control block containing additional options
 *
 * Return: Error code, or length of message
 */
int batadv_get_option_dump(struct sk_buff *msg, struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	unsigned int start = cb->args[0];
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;
	unsigned int i;
	int ifindex;
	int ret;

	ifindex = batadv_netlink_get_ifindex(cb->nlh,
					     BATADV_ATTR_MESH_IFINDEX);
	if (!ifindex)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	for (i = start; i < ARRAY_SIZE(softif_options); i++) {
		ret = batadv_get_option_fill(msg, bat_priv, &softif_options[i],
					     NULL, BATADV_CMD_GET_OPTION,
					     NETLINK_CB(cb->skb).portid,
					     cb->nlh->nlmsg_seq,
					     NLM_F_MULTI);
		if (ret == -EOPNOTSUPP)
			continue;
		if (ret < 0)
			break;
	}

	cb->args[0] = i;
	ret = msg->len;

err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_option_hardif_notify() - send new hardif option value to listener
 * @bat_priv: the bat priv with all the soft interface information
 * @hard_iface: hard interface which was modified
 * @option: option which was modified
 *
 * Return: 0 on success, < 0 on error
 */
static int batadv_option_hardif_notify(struct batadv_priv *bat_priv,
				       struct batadv_hard_iface *hard_iface,
				       const struct batadv_option *option)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = batadv_get_option_fill_open(msg, &hdr, bat_priv, option,
					  hard_iface,
					  BATADV_CMD_SET_OPTION_HARDIF, 0, 0,
					  0);
	if (ret < 0)
		goto nla_put_failure;

	if (nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX,
			bat_priv->soft_iface->ifindex))
		goto nla_put_failure;

	if (nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			hard_iface->net_dev->ifindex))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&batadv_netlink_family,
				dev_net(bat_priv->soft_iface), msg, 0,
				BATADV_NL_MCGRP_CONFIG, GFP_KERNEL);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	ret = -EMSGSIZE;
	nlmsg_free(msg);
	return ret;
}

/**
 * batadv_get_option_hardif() - Get hardif option
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
int batadv_get_option_hardif(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct batadv_hard_iface *hard_iface;
	const struct batadv_option *option;
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;
	struct net_device *hard_dev;
	unsigned int hardif_index;
	const char *option_name;
	struct sk_buff *msg;
	int ifindex;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_HARD_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_NAME])
		return -EINVAL;

	option_name = nla_data(info->attrs[BATADV_ATTR_OPTION_NAME]);
	option = batadv_find_option(option_name, hardif_options,
				    ARRAY_SIZE(hardif_options));
	if (!option)
		return -EOPNOTSUPP;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	hardif_index = nla_get_u32(info->attrs[BATADV_ATTR_HARD_IFINDEX]);
	hard_dev = dev_get_by_index(net, hardif_index);
	if (!hard_dev) {
		ret = -ENODEV;
		goto err_put_softif;
	}

	hard_iface = batadv_hardif_get_by_netdev(hard_dev);
	if (!hard_iface) {
		ret = -EINVAL;
		goto err_put_harddev;
	}

	if (hard_iface->soft_iface != soft_iface) {
		ret = -EINVAL;
		goto err_put_hardif;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto err_put_hardif;
	}

	ret = batadv_get_option_fill(msg, bat_priv, option, hard_iface,
				     BATADV_CMD_GET_OPTION_HARDIF,
				     info->snd_portid, info->snd_seq, 0);
	if (ret < 0) {
		nlmsg_free(msg);
		goto err_put_hardif;
	}

	ret = genlmsg_reply(msg, info);

err_put_hardif:
	batadv_hardif_put(hard_iface);
err_put_harddev:
	dev_put(hard_dev);
err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_set_option_hardif() - Set hardif option
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
int batadv_set_option_hardif(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct batadv_hard_iface *hard_iface;
	const struct batadv_option *option;
	struct net_device *soft_iface;
	union batadv_config_value val;
	struct batadv_priv *bat_priv;
	struct net_device *hard_dev;
	unsigned int hardif_index;
	const char *option_name;
	int option_type;
	int ifindex;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_HARD_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_NAME])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_TYPE])
		return -EINVAL;

	option_name = nla_data(info->attrs[BATADV_ATTR_OPTION_NAME]);
	option = batadv_find_option(option_name, hardif_options,
				    ARRAY_SIZE(hardif_options));
	if (!option)
		return -EOPNOTSUPP;

	option_type = nla_get_u8(info->attrs[BATADV_ATTR_OPTION_TYPE]);
	if (option_type != option->type)
		return -EINVAL;

	ret = batadv_option_value_get_from_info(option, info, &val);
	if (ret < 0)
		return ret;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	hardif_index = nla_get_u32(info->attrs[BATADV_ATTR_HARD_IFINDEX]);
	hard_dev = dev_get_by_index(net, hardif_index);
	if (!hard_dev) {
		ret = -ENODEV;
		goto err_put_softif;
	}

	hard_iface = batadv_hardif_get_by_netdev(hard_dev);
	if (!hard_iface) {
		ret = -EINVAL;
		goto err_put_harddev;
	}

	if (hard_iface->soft_iface != soft_iface) {
		ret = -EINVAL;
		goto err_put_hardif;
	}

	ret = option->set(bat_priv, hard_iface, &val);
	if (ret < 0)
		goto err_put_hardif;

	batadv_option_hardif_notify(bat_priv, hard_iface, option);

err_put_hardif:
	batadv_hardif_put(hard_iface);
err_put_harddev:
	dev_put(hard_dev);
err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_get_option_hardif_dump() - Dump hardif options into a message
 * @msg: Netlink message to dump into
 * @cb: Control block containing additional options
 *
 * Return: Error code, or length of message
 */
int batadv_get_option_hardif_dump(struct sk_buff *msg,
				  struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	struct batadv_hard_iface *hard_iface;
	unsigned int start = cb->args[0];
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;
	struct net_device *hard_dev;
	unsigned int hardif_index;
	unsigned int i;
	int ifindex;
	int ret;

	ifindex = batadv_netlink_get_ifindex(cb->nlh,
					     BATADV_ATTR_MESH_IFINDEX);
	if (!ifindex)
		return -EINVAL;

	hardif_index = batadv_netlink_get_ifindex(cb->nlh,
						  BATADV_ATTR_HARD_IFINDEX);
	if (!hardif_index)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	hard_dev = dev_get_by_index(net, hardif_index);
	if (!hard_dev) {
		ret = -ENODEV;
		goto err_put_softif;
	}

	hard_iface = batadv_hardif_get_by_netdev(hard_dev);
	if (!hard_iface) {
		ret = -EINVAL;
		goto err_put_harddev;
	}

	if (hard_iface->soft_iface != soft_iface) {
		ret = -EINVAL;
		goto err_put_hardif;
	}

	for (i = start; i < ARRAY_SIZE(hardif_options); i++) {
		ret = batadv_get_option_fill(msg, bat_priv, &hardif_options[i],
					     hard_iface,
					     BATADV_CMD_GET_OPTION_HARDIF,
					     NETLINK_CB(cb->skb).portid,
					     cb->nlh->nlmsg_seq,
					     NLM_F_MULTI);
		if (ret == -EOPNOTSUPP)
			continue;
		if (ret < 0)
			break;
	}

	cb->args[0] = i;
	ret = msg->len;

err_put_hardif:
	batadv_hardif_put(hard_iface);
err_put_harddev:
	dev_put(hard_dev);
err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_option_vlan_notify() - send new vlan option value to listener
 * @bat_priv: the bat priv with all the soft interface information
 * @vlan: vlan which was modified
 * @option: option which was modified
 *
 * Return: 0 on success, < 0 on error
 */
static int batadv_option_vlan_notify(struct batadv_priv *bat_priv,
				     struct batadv_softif_vlan *vlan,
				     const struct batadv_option *option)
{
	struct sk_buff *msg;
	void *hdr;
	int ret;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = batadv_get_option_fill_open(msg, &hdr, bat_priv, option, vlan,
					  BATADV_CMD_SET_OPTION_VLAN, 0, 0, 0);
	if (ret < 0)
		goto nla_put_failure;

	if (nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX,
			bat_priv->soft_iface->ifindex))
		goto nla_put_failure;

	if (nla_put_u32(msg, BATADV_ATTR_VLANID, vlan->vid & VLAN_VID_MASK))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&batadv_netlink_family,
				dev_net(bat_priv->soft_iface), msg, 0,
				BATADV_NL_MCGRP_CONFIG, GFP_KERNEL);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	ret = -EMSGSIZE;
	nlmsg_free(msg);
	return ret;
}

/**
 * batadv_get_option_vlan() - Get vlan option
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: Error code, or length of message
 */
int batadv_get_option_vlan(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	const struct batadv_option *option;
	struct batadv_softif_vlan *vlan;
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;
	const char *option_name;
	struct sk_buff *msg;
	int ifindex;
	u16 vid;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_VLANID])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_NAME])
		return -EINVAL;

	option_name = nla_data(info->attrs[BATADV_ATTR_OPTION_NAME]);
	option = batadv_find_option(option_name, vlan_options,
				    ARRAY_SIZE(vlan_options));
	if (!option)
		return -EOPNOTSUPP;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	vid = nla_get_u16(info->attrs[BATADV_ATTR_VLANID]);
	vlan = batadv_softif_vlan_get(bat_priv, vid | BATADV_VLAN_HAS_TAG);
	if (!vlan) {
		ret = -ENOENT;
		goto err_put_softif;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto err_put_vlan;
	}

	ret = batadv_get_option_fill(msg, bat_priv, option,
				     vlan, BATADV_CMD_GET_OPTION_VLAN,
				     info->snd_portid, info->snd_seq, 0);
	if (ret < 0) {
		nlmsg_free(msg);
		goto err_put_vlan;
	}

	ret = genlmsg_reply(msg, info);

err_put_vlan:
	batadv_softif_vlan_put(vlan);
err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_set_option_vlan() - Get vlan option
 * @skb: Netlink message with request data
 * @info: receiver information
 *
 * Return: 0 on success or negative error number in case of failure
 */
int batadv_set_option_vlan(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	const struct batadv_option *option;
	struct batadv_softif_vlan *vlan;
	struct net_device *soft_iface;
	union batadv_config_value val;
	struct batadv_priv *bat_priv;
	const char *option_name;
	int option_type;
	int ifindex;
	u16 vid;
	int ret;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_VLANID])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_NAME])
		return -EINVAL;

	if (!info->attrs[BATADV_ATTR_OPTION_TYPE])
		return -EINVAL;

	option_name = nla_data(info->attrs[BATADV_ATTR_OPTION_NAME]);
	option = batadv_find_option(option_name, vlan_options,
				    ARRAY_SIZE(vlan_options));
	if (!option)
		return -EOPNOTSUPP;

	option_type = nla_get_u8(info->attrs[BATADV_ATTR_OPTION_TYPE]);
	if (option_type != option->type)
		return -EINVAL;

	ret = batadv_option_value_get_from_info(option, info, &val);
	if (ret < 0)
		return ret;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	vid = nla_get_u16(info->attrs[BATADV_ATTR_VLANID]);
	vlan = batadv_softif_vlan_get(bat_priv, vid | BATADV_VLAN_HAS_TAG);
	if (!vlan) {
		ret = -ENOENT;
		goto err_put_softif;
	}

	ret = option->set(bat_priv, vlan, &val);
	if (ret < 0)
		goto err_put_vlan;

	batadv_option_vlan_notify(bat_priv, vlan, option);

err_put_vlan:
	batadv_softif_vlan_put(vlan);
err_put_softif:
	dev_put(soft_iface);

	return ret;
}

/**
 * batadv_get_option_vlan_dump() - Dump vlan options into a message
 * @msg: Netlink message to dump into
 * @cb: Control block containing additional options
 *
 * Return: Error code, or length of message
 */
int batadv_get_option_vlan_dump(struct sk_buff *msg,
				struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	unsigned int start = cb->args[0];
	struct batadv_softif_vlan *vlan;
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;
	struct nlattr *vid_attr;
	unsigned int i;
	int ifindex;
	u16 vid;
	int ret;

	vid_attr = nlmsg_find_attr(cb->nlh, GENL_HDRLEN, BATADV_ATTR_VLANID);
	if (!vid_attr)
		return -EINVAL;

	ifindex = batadv_netlink_get_ifindex(cb->nlh,
					     BATADV_ATTR_MESH_IFINDEX);
	if (!ifindex)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		ret = -EINVAL;
		goto err_put_softif;
	}

	bat_priv = netdev_priv(soft_iface);

	vid = nla_get_u16(vid_attr);
	vlan = batadv_softif_vlan_get(bat_priv, vid | BATADV_VLAN_HAS_TAG);
	if (!vlan) {
		ret = -ENOENT;
		goto err_put_softif;
	}

	for (i = start; i < ARRAY_SIZE(vlan_options); i++) {
		ret = batadv_get_option_fill(msg, bat_priv, &vlan_options[i],
					     vlan, BATADV_CMD_GET_OPTION_VLAN,
					     NETLINK_CB(cb->skb).portid,
					     cb->nlh->nlmsg_seq,
					     NLM_F_MULTI);
		if (ret == -EOPNOTSUPP)
			continue;
		if (ret < 0)
			break;
	}

	cb->args[0] = i;
	ret = msg->len;

	batadv_softif_vlan_put(vlan);
err_put_softif:
	dev_put(soft_iface);

	return ret;
}
