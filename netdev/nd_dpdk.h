#ifndef __NETDEV_DPDK_H
#define __NETDEV_DPDK_H

#include "cmn_base.h"
#include "cmn_log.h"

#include "rte_version.h"
#if (RTE_VER_YEAR > 17) || (RTE_VER_YEAR == 17 && RTE_VER_MONTH >= 11)
#include "rte_bus_pci.h"
#endif
#include "rte_pci.h"
#include "rte_config.h"
#include "rte_ethdev.h"
#include "rte_errno.h"
#include "rte_malloc.h"
#include "rte_cycles.h"

#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>


#define MAX_BURST_SIZE 64
#define MEMPOOL_CACHE_SIZE 256

#define DPDK_COFIG_HEADER_SPLIT         0 /**< Header Split disabled */
#define DPDK_COFIG_SPLIT_HEADER_SIZE    0
#define DPDK_COFIG_HW_IP_CHECKSUM       0 /**< IP checksum offload disabled */
#define DPDK_COFIG_HW_VLAN_FILTER       0 /**< VLAN filtering disabled */
#define DPDK_COFIG_JUMBO_FRAME          0 /**< Jumbo Frame Support disabled */
#define DPDK_COFIG_HW_STRIP_CRC         0 /**< CRC stripped by hardware disabled */
#define DPDK_CONFIG_MQ_MODE             ETH_RSS

//RSS random key:
uint8_t RSSKey[40] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

#endif
