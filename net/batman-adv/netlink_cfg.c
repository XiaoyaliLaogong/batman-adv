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

#include <linux/atomic.h>
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

#include "bridge_loop_avoidance.h"
#include "distributed-arp-table.h"
#include "gateway_client.h"
#include "gateway_common.h"
#include "hard-interface.h"
#include "log.h"
#include "netlink.h"
#include "soft-interface.h"

/**
 * batadv_option_get_aggregated_ogms() - Retrieve aggregated_ogms option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_aggregated_ogms(struct batadv_priv *bat_priv,
					     void *ext_arg,
					     union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->aggregated_ogms);
	return 0;
}

/**
 * batadv_option_set_aggregated_ogms() - Set aggregated_ogms option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_aggregated_ogms(struct batadv_priv *bat_priv, void *ext_arg,
				  const union batadv_config_value *val)
{
	atomic_set(&bat_priv->aggregated_ogms, val->vbool);
	return 0;
}

/**
 * batadv_option_get_ap_isolation() - Retrieve ap_isolation option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_ap_isolation(struct batadv_priv *bat_priv,
					  void *ext_arg,
					  union batadv_config_value *val)
{
	struct batadv_softif_vlan *vlan;

	vlan = batadv_softif_vlan_get(bat_priv, BATADV_NO_FLAGS);
	if (!vlan)
		return -ENOENT;

	val->vbool = !!atomic_read(&vlan->ap_isolation);
	batadv_softif_vlan_put(vlan);

	return 0;
}

/**
 * batadv_option_set_ap_isolation() - Set ap_isolation option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_ap_isolation(struct batadv_priv *bat_priv,
					  void *ext_arg,
					  const union batadv_config_value *val)
{
	struct batadv_softif_vlan *vlan;

	vlan = batadv_softif_vlan_get(bat_priv, BATADV_NO_FLAGS);
	if (!vlan)
		return -ENOENT;

	atomic_set(&vlan->ap_isolation, val->vbool);
	batadv_softif_vlan_put(vlan);

	return 0;
}

/**
 * batadv_option_get_bonding() - Retrieve bonding option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_bonding(struct batadv_priv *bat_priv,
				     void *ext_arg,
				     union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->bonding);
	return 0;
}

/**
 * batadv_option_set_bonding() - Set bonding option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_bonding(struct batadv_priv *bat_priv,
				     void *ext_arg,
				     const union batadv_config_value *val)
{
	atomic_set(&bat_priv->bonding, val->vbool);
	return 0;
}

#ifdef CONFIG_BATMAN_ADV_BLA

/**
 * batadv_option_get_bridge_loop_avoidance() - Retrieve bridge_loop_avoidance
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_get_bridge_loop_avoidance(struct batadv_priv *bat_priv,
					void *ext_arg,
					union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->bridge_loop_avoidance);
	return 0;
}

/**
 * batadv_option_set_bridge_loop_avoidance() - Set bridge_loop_avoidance option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_bridge_loop_avoidance(struct batadv_priv *bat_priv,
					void *ext_arg,
					const union batadv_config_value *val)
{
	atomic_set(&bat_priv->bridge_loop_avoidance, val->vbool);
	batadv_bla_status_update(bat_priv->soft_iface);
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_BLA */

#ifdef CONFIG_BATMAN_ADV_DAT

/**
 * batadv_option_get_distributed_arp_table() - Retrieve distributed_arp_table
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_get_distributed_arp_table(struct batadv_priv *bat_priv,
					void *ext_arg,
					union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->distributed_arp_table);
	return 0;
}

/**
 * batadv_option_set_distributed_arp_table() - Set distributed_arp_table option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_distributed_arp_table(struct batadv_priv *bat_priv,
					void *ext_arg,
					const union batadv_config_value *val)
{
	atomic_set(&bat_priv->distributed_arp_table, val->vbool);
	batadv_dat_status_update(bat_priv->soft_iface);
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_DAT */

/**
 * batadv_option_get_fragmentation() - Retrieve fragmentation
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_fragmentation(struct batadv_priv *bat_priv,
					   void *ext_arg,
					   union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->fragmentation);
	return 0;
}

/**
 * batadv_option_set_fragmentation() - Set fragmentation option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_fragmentation(struct batadv_priv *bat_priv,
					   void *ext_arg,
					   const union batadv_config_value *val)
{
	atomic_set(&bat_priv->fragmentation, val->vbool);
	batadv_update_min_mtu(bat_priv->soft_iface);
	return 0;
}

/**
 * batadv_option_get_gw_bandwidth_down() - Retrieve gw_bandwidth_down
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_gw_bandwidth_down(struct batadv_priv *bat_priv,
					       void *ext_arg,
					       union batadv_config_value *val)
{
	val->vu32 = atomic_read(&bat_priv->gw.bandwidth_down);
	return 0;
}

/**
 * batadv_option_set_gw_bandwidth_down() - Set gw_bandwidth_down option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_gw_bandwidth_down(struct batadv_priv *bat_priv, void *ext_arg,
				    const union batadv_config_value *val)
{
	atomic_set(&bat_priv->gw.bandwidth_down, val->vu32);
	batadv_gw_tvlv_container_update(bat_priv);
	return 0;
}

/**
 * batadv_option_get_gw_bandwidth_up() - Retrieve gw_bandwidth_up
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_gw_bandwidth_up(struct batadv_priv *bat_priv,
					     void *ext_arg,
					     union batadv_config_value *val)
{
	val->vu32 = atomic_read(&bat_priv->gw.bandwidth_up);
	return 0;
}

/**
 * batadv_option_set_gw_bandwidth_up() - Set gw_bandwidth_up option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_gw_bandwidth_up(struct batadv_priv *bat_priv, void *ext_arg,
				  const union batadv_config_value *val)
{
	atomic_set(&bat_priv->gw.bandwidth_up, val->vu32);
	batadv_gw_tvlv_container_update(bat_priv);
	return 0;
}

/**
 * batadv_option_get_gw_mode() - Retrieve gw_mode
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save string
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_gw_mode(struct batadv_priv *bat_priv,
				     void *ext_arg,
				     union batadv_config_value *val)
{
	/* GW mode is not available if the routing algorithm in use does not
	 * implement the GW API
	 */
	if (!bat_priv->algo_ops->gw.get_best_gw_node ||
	    !bat_priv->algo_ops->gw.is_eligible)
		return -EOPNOTSUPP;

	switch (atomic_read(&bat_priv->gw.mode)) {
	case BATADV_GW_MODE_CLIENT:
		strlcpy(val->string, BATADV_GW_MODE_CLIENT_NAME,
			sizeof(val->string));
		break;
	case BATADV_GW_MODE_SERVER:
		strlcpy(val->string, BATADV_GW_MODE_SERVER_NAME,
			sizeof(val->string));
		break;
	default:
		strlcpy(val->string, BATADV_GW_MODE_OFF_NAME,
			sizeof(val->string));
		break;
	}

	return 0;
}

/**
 * batadv_option_set_gw_mode() - Set gw_mode option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: string value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_gw_mode(struct batadv_priv *bat_priv,
				     void *ext_arg,
				     const union batadv_config_value *val)
{
	int gw_mode_tmp = BATADV_GW_MODE_OFF;

	if (strcmp(val->string, BATADV_GW_MODE_OFF_NAME) == 0)
		gw_mode_tmp = BATADV_GW_MODE_OFF;

	if (strcmp(val->string, BATADV_GW_MODE_CLIENT_NAME) == 0)
		gw_mode_tmp = BATADV_GW_MODE_CLIENT;

	if (strcmp(val->string, BATADV_GW_MODE_SERVER_NAME) == 0)
		gw_mode_tmp = BATADV_GW_MODE_SERVER;

	/* Invoking batadv_gw_reselect() is not enough to really de-select the
	 * current GW. It will only instruct the gateway client code to perform
	 * a re-election the next time that this is needed.
	 *
	 * When gw client mode is being switched off the current GW must be
	 * de-selected explicitly otherwise no GW_ADD uevent is thrown on
	 * client mode re-activation. This is operation is performed in
	 * batadv_gw_check_client_stop().
	 */
	batadv_gw_reselect(bat_priv);
	/* always call batadv_gw_check_client_stop() before changing the gateway
	 * state
	 */
	batadv_gw_check_client_stop(bat_priv);
	atomic_set(&bat_priv->gw.mode, (unsigned int)gw_mode_tmp);
	batadv_gw_tvlv_container_update(bat_priv);

	return 0;
}

/**
 * batadv_option_validate_gw_mode() - Validate gw_mode option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: string value of option to validate
 * @extack: additional information about error
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_validate_gw_mode(struct batadv_priv *bat_priv,
					  void *ext_arg,
					  const union batadv_config_value *val,
					  struct netlink_ext_ack *extack)
{
	const char *str = val->string;

	if (strcmp(BATADV_GW_MODE_OFF_NAME, str) == 0)
		return 0;

	if (strcmp(BATADV_GW_MODE_CLIENT_NAME, str) == 0)
		return 0;

	if (strcmp(BATADV_GW_MODE_SERVER_NAME, str) == 0)
		return 0;

	return -EINVAL;
}

/**
 * batadv_option_get_gw_sel_class() - Retrieve gw_sel_class
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_gw_sel_class(struct batadv_priv *bat_priv,
					  void *ext_arg,
					  union batadv_config_value *val)
{
	/* GW selection class is not available if the routing algorithm in use
	 * does not implement the GW API
	 */
	if (!bat_priv->algo_ops->gw.get_best_gw_node ||
	    !bat_priv->algo_ops->gw.is_eligible)
		return -EOPNOTSUPP;

	val->vu32 = atomic_read(&bat_priv->gw.sel_class);

	return 0;
}

/**
 * batadv_option_set_gw_sel_class() - Set gw_sel_class option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_gw_sel_class(struct batadv_priv *bat_priv,
					  void *ext_arg,
					  const union batadv_config_value *val)
{
	atomic_set(&bat_priv->gw.sel_class, val->vu32);
	batadv_gw_reselect(bat_priv);
	return 0;
}

/**
 * batadv_option_validate_gw_sel_class() - Validate gw_sel_class option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to validate
 * @extack: additional information about error
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_validate_gw_sel_class(struct batadv_priv *bat_priv, void *ext_arg,
				    const union batadv_config_value *val,
				    struct netlink_ext_ack *extack)
{
	u32 value = val->vu32;

	/* setting the GW selection class is allowed only if the routing
	 * algorithm in use implements the GW API
	 */
	if (!bat_priv->algo_ops->gw.get_best_gw_node ||
	    !bat_priv->algo_ops->gw.is_eligible)
		return -EOPNOTSUPP;

	if (!bat_priv->algo_ops->gw.store_sel_class) {
		if (value < 1 || value > BATADV_TQ_MAX_VALUE)
			return -ERANGE;
	}

	return 0;
}

/**
 * batadv_option_get_hop_penalty() - Retrieve hop_penalty
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_hop_penalty(struct batadv_priv *bat_priv,
					 void *ext_arg,
					 union batadv_config_value *val)
{
	val->vu32 = atomic_read(&bat_priv->hop_penalty);
	return 0;
}

/**
 * batadv_option_set_hop_penalty() - Set hop_penalty option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_hop_penalty(struct batadv_priv *bat_priv,
					 void *ext_arg,
					 const union batadv_config_value *val)
{
	atomic_set(&bat_priv->hop_penalty, val->vu32);
	return 0;
}

/**
 * batadv_option_validate_hop_penalty() - Validate hop_penalty option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to validate
 * @extack: additional information about error
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_validate_hop_penalty(struct batadv_priv *bat_priv, void *ext_arg,
				   const union batadv_config_value *val,
				   struct netlink_ext_ack *extack)
{
	u32 value = val->vu32;

	if (value > BATADV_TQ_MAX_VALUE)
		return -ERANGE;

	return 0;
}

#ifdef CONFIG_BATMAN_ADV_DEBUG

/**
 * batadv_option_get_log_level() - Retrieve log_level
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_log_level(struct batadv_priv *bat_priv,
				       void *ext_arg,
				       union batadv_config_value *val)
{
	val->vu32 = atomic_read(&bat_priv->log_level);
	return 0;
}

/**
 * batadv_option_set_log_level() - Set log_level option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_log_level(struct batadv_priv *bat_priv,
				       void *ext_arg,
				       const union batadv_config_value *val)
{
	atomic_set(&bat_priv->log_level, val->vu32);
	return 0;
}

/**
 * batadv_option_validate_log_level() - Validate log_level option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to validate
 * @extack: additional information about error
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_validate_log_level(struct batadv_priv *bat_priv, void *ext_arg,
				 const union batadv_config_value *val,
				 struct netlink_ext_ack *extack)
{
	u32 value = val->vu32;

	if (value > BATADV_DBG_ALL)
		return -ERANGE;
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_DEBUG */

#ifdef CONFIG_BATMAN_ADV_MCAST

/**
 * batadv_option_get_multicast_mode() - Retrieve multicast_mode option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_multicast_mode(struct batadv_priv *bat_priv,
					    void *ext_arg,
					    union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->multicast_mode);
	return 0;
}

/**
 * batadv_option_set_multicast_mode() - Set multicast_mode option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_multicast_mode(struct batadv_priv *bat_priv, void *ext_arg,
				 const union batadv_config_value *val)
{
	atomic_set(&bat_priv->multicast_mode, val->vbool);
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_MCAST */

#ifdef CONFIG_BATMAN_ADV_NC

/**
 * batadv_option_get_network_coding() - Retrieve network_coding option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_network_coding(struct batadv_priv *bat_priv,
					    void *ext_arg,
					    union batadv_config_value *val)
{
	val->vbool = !!atomic_read(&bat_priv->network_coding);
	return 0;
}

/**
 * batadv_option_set_network_coding() - Set network_coding option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_network_coding(struct batadv_priv *bat_priv, void *ext_arg,
				 const union batadv_config_value *val)
{
	atomic_set(&bat_priv->network_coding, val->vbool);
	batadv_nc_status_update(bat_priv->soft_iface);
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_NC */

/**
 * batadv_option_get_isolation_mark() - Retrieve isolation_mark
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_isolation_mark(struct batadv_priv *bat_priv,
					    void *ext_arg,
					    union batadv_config_value *val)
{
	val->vu32 = bat_priv->isolation_mark;
	return 0;
}

/**
 * batadv_option_set_isolation_mark() - Set isolation_mark option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_isolation_mark(struct batadv_priv *bat_priv, void *ext_arg,
				 const union batadv_config_value *val)
{
	bat_priv->isolation_mark = val->vu32;
	return 0;
}

/**
 * batadv_option_get_isolation_mask() - Retrieve isolation_mask
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_isolation_mask(struct batadv_priv *bat_priv,
					    void *ext_arg,
					    union batadv_config_value *val)
{
	val->vu32 = bat_priv->isolation_mark_mask;
	return 0;
}

/**
 * batadv_option_set_isolation_mask() - Set isolation_mask option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_set_isolation_mask(struct batadv_priv *bat_priv, void *ext_arg,
				 const union batadv_config_value *val)
{
	bat_priv->isolation_mark_mask = val->vu32;
	return 0;
}

/**
 * batadv_option_get_orig_interval() - Retrieve orig_interval
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_get_orig_interval(struct batadv_priv *bat_priv,
					   void *ext_arg,
					   union batadv_config_value *val)
{
	val->vu32 = atomic_read(&bat_priv->orig_interval);
	return 0;
}

/**
 * batadv_option_set_orig_interval() - Set orig_interval option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_set_orig_interval(struct batadv_priv *bat_priv,
					   void *ext_arg,
					   const union batadv_config_value *val)
{
	atomic_set(&bat_priv->orig_interval, val->vu32);
	return 0;
}

/**
 * batadv_option_validate_orig_interval() - Validate orig_interval option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: Additional option element (unused)
 * @val: u32 value of option to validate
 * @extack: additional information about error
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_validate_orig_interval(struct batadv_priv *bat_priv,
				     void *ext_arg,
				     const union batadv_config_value *val,
				     struct netlink_ext_ack *extack)
{
	u32 value = val->vu32;

	if (value < 2 * BATADV_JITTER || value > INT_MAX)
		return -ERANGE;

	return 0;
}

static const struct batadv_option softif_options[] = {
	{
		.name = "aggregated_ogms",
		.type = NLA_FLAG,
		.get = batadv_option_get_aggregated_ogms,
		.set = batadv_option_set_aggregated_ogms,
	},
	{
		.name = "ap_isolation",
		.type = NLA_FLAG,
		.get = batadv_option_get_ap_isolation,
		.set = batadv_option_set_ap_isolation,
	},
	{
		.name = "bonding",
		.type = NLA_FLAG,
		.get = batadv_option_get_bonding,
		.set = batadv_option_set_bonding,
	},
#ifdef CONFIG_BATMAN_ADV_BLA
	{
		.name = "bridge_loop_avoidance",
		.type = NLA_FLAG,
		.get = batadv_option_get_bridge_loop_avoidance,
		.set = batadv_option_set_bridge_loop_avoidance,
	},
#endif /* CONFIG_BATMAN_ADV_BLA */
#ifdef CONFIG_BATMAN_ADV_DAT
	{
		.name = "distributed_arp_table",
		.type = NLA_FLAG,
		.get = batadv_option_get_distributed_arp_table,
		.set = batadv_option_set_distributed_arp_table,
	},
#endif /* CONFIG_BATMAN_ADV_DAT */
	{
		.name = "fragmentation",
		.type = NLA_FLAG,
		.get = batadv_option_get_fragmentation,
		.set = batadv_option_set_fragmentation,
	},
	{
		.name = "gw_bandwidth_down",
		.type = NLA_U32,
		.get = batadv_option_get_gw_bandwidth_down,
		.set = batadv_option_set_gw_bandwidth_down,
	},
	{
		.name = "gw_bandwidth_up",
		.type = NLA_U32,
		.get = batadv_option_get_gw_bandwidth_up,
		.set = batadv_option_set_gw_bandwidth_up,
	},
	{
		.name = "gw_mode",
		.type = NLA_NUL_STRING,
		.get = batadv_option_get_gw_mode,
		.set = batadv_option_set_gw_mode,
		.validate = batadv_option_validate_gw_mode,
	},
	{
		.name = "gw_sel_class",
		.type = NLA_U32,
		.get = batadv_option_get_gw_sel_class,
		.set = batadv_option_set_gw_sel_class,
		.validate = batadv_option_validate_gw_sel_class,
	},
	{
		.name = "hop_penalty",
		.type = NLA_U32,
		.get = batadv_option_get_hop_penalty,
		.set = batadv_option_set_hop_penalty,
		.validate = batadv_option_validate_hop_penalty,
	},
#ifdef CONFIG_BATMAN_ADV_DEBUG
	{
		.name = "log_level",
		.type = NLA_U32,
		.get = batadv_option_get_log_level,
		.set = batadv_option_set_log_level,
		.validate = batadv_option_validate_log_level,
	},
#endif /* CONFIG_BATMAN_ADV_DEBUG */
#ifdef CONFIG_BATMAN_ADV_MCAST
	{
		.name = "multicast_mode",
		.type = NLA_FLAG,
		.get = batadv_option_get_multicast_mode,
		.set = batadv_option_set_multicast_mode,
	},
#endif /* CONFIG_BATMAN_ADV_MCAST */
#ifdef CONFIG_BATMAN_ADV_NC
	{
		.name = "network_coding",
		.type = NLA_FLAG,
		.get = batadv_option_get_network_coding,
		.set = batadv_option_set_network_coding,
	},
#endif /* CONFIG_BATMAN_ADV_NC */
	{
		.name = "isolation_mark",
		.type = NLA_U32,
		.get = batadv_option_get_isolation_mark,
		.set = batadv_option_set_isolation_mark,
	},
	{
		.name = "isolation_mask",
		.type = NLA_U32,
		.get = batadv_option_get_isolation_mask,
		.set = batadv_option_set_isolation_mask,
	},
	{
		.name = "orig_interval",
		.type = NLA_U32,
		.get = batadv_option_get_orig_interval,
		.set = batadv_option_set_orig_interval,
		.validate = batadv_option_validate_orig_interval,
	},
};

#ifdef CONFIG_BATMAN_ADV_BATMAN_V

/**
 * batadv_option_get_elp_interval() - Retrieve elp_interval
 *  option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: hard interface object with option
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_hardif_get_elp_interval(struct batadv_priv *bat_priv,
						 void *ext_arg,
						 union batadv_config_value *val)
{
	struct batadv_hard_iface *hard_iface = ext_arg;

	val->vu32 = atomic_read(&hard_iface->bat_v.elp_interval);
	return 0;
}

/**
 * batadv_option_set_elp_interval() - Set elp_interval option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: hard interface object to modify
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_hardif_set_elp_interval(struct batadv_priv *bat_priv,
				      void *ext_arg,
				      const union batadv_config_value *val)
{
	struct batadv_hard_iface *hard_iface = ext_arg;

	atomic_set(&hard_iface->bat_v.elp_interval, val->vu32);
	return 0;
}

/**
 * batadv_option_hardif_get_tp_override() - Retrieve throughput_override option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: hard interface object with option
 * @val: Target to save u32
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_hardif_get_tp_override(struct batadv_priv *bat_priv,
						void *ext_arg,
						union batadv_config_value *val)
{
	struct batadv_hard_iface *hard_iface = ext_arg;

	val->vu32 = atomic_read(&hard_iface->bat_v.throughput_override);
	return 0;
}

/**
 * batadv_option_hardif_set_tp_override() - Set throughput_override option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: hard interface object to modify
 * @val: u32 value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_hardif_set_tp_override(struct batadv_priv *bat_priv,
				     void *ext_arg,
				     const union batadv_config_value *val)
{
	struct batadv_hard_iface *hard_iface = ext_arg;

	atomic_set(&hard_iface->bat_v.throughput_override, val->vu32);
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_BATMAN_V */

static const struct batadv_option hardif_options[] = {
#ifdef CONFIG_BATMAN_ADV_BATMAN_V
	{
		.name = "elp_interval",
		.type = NLA_U32,
		.get = batadv_option_hardif_get_elp_interval,
		.set = batadv_option_hardif_set_elp_interval,
	},
	{
		.name = "throughput_override",
		.type = NLA_U32,
		.get = batadv_option_hardif_get_tp_override,
		.set = batadv_option_hardif_set_tp_override,
	},
#endif /* CONFIG_BATMAN_ADV_BATMAN_V */
};

/**
 * batadv_option_get_ap_isolation() - Retrieve ap_isolation option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: vlan to modify
 * @val: Target to save boolean
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int batadv_option_vlan_get_ap_isolation(struct batadv_priv *bat_priv,
					       void *ext_arg,
					       union batadv_config_value *val)
{
	struct batadv_softif_vlan *vlan = ext_arg;

	val->vbool = !!atomic_read(&vlan->ap_isolation);

	return 0;
}

/**
 * batadv_option_set_ap_isolation() - Set ap_isolation option
 * @bat_priv: the bat priv with all the soft interface information
 * @ext_arg: vlan to modify
 * @val: Boolean value of option to set
 *
 * Return: 0 on success or negative error number in case of failure
 */
static int
batadv_option_vlan_set_ap_isolation(struct batadv_priv *bat_priv,
				    void *ext_arg,
				    const union batadv_config_value *val)
{
	struct batadv_softif_vlan *vlan = ext_arg;

	atomic_set(&vlan->ap_isolation, val->vbool);

	return 0;
}

static const struct batadv_option vlan_options[] = {
	{
		.name = "ap_isolation",
		.type = NLA_FLAG,
		.get = batadv_option_vlan_get_ap_isolation,
		.set = batadv_option_vlan_set_ap_isolation,
	},
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
