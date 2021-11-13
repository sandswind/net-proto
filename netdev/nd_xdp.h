#ifndef __ND_XDP_H
#define __ND_XDP_H

#include <net/if.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cmn_log.h"
#include "cmn_base.h"

#define MAX_IFNAME_LEN 256
#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#ifndef XDP_MAX_HITS
#define XDP_MAX_HITS (3)
#endif

#define MAP_DIR             "/sys/fs/bpf"
#define MAC_BLACKLIST_PATH  "/sys/fs/bpf/mac_blacklist"
#define V4_BLACKLIST_PATH   "/sys/fs/bpf/v4_blacklist"
#define VIP_MAP_PATH        "/sys/fs/bpf/vip_map"
#define COUNTER_MAP_PATH    "/sys/fs/bpf/action_counter"
#define EVENT_MAP_PATH      "/sys/fs/bpf/perf_map"
#define HIT_MAP_PATH        "/sys/fs/bpf/hit_counter"

static char *xdp_action_names[XDP_MAX_ACTIONS] = {
    [XDP_ABORTED]   = "XDP_ABORTED",
    [XDP_DROP]      = "XDP_DROP",
    [XDP_PASS]      = "XDP_PASS",
    [XDP_TX]        = "XDP_TX",
    [XDP_REDIRECT]  = "XDP_REDIRECT",
};

static char *xdp_hit_names[XDP_MAX_HITS] = {
    [0]   = "MAC_BLACKLIST_HIT",
    [1]   = "V4_BLACKLIST_HIT",
    [2]   = "VIP_NOHIT",
};

static inline char *action2str(uint32_t action)
{
    if (action < XDP_MAX_ACTIONS)
        return xdp_action_names[action];

    return NULL;
}

static inline char *hit2str(uint32_t action)
{
    if (action < XDP_MAX_HITS)
        return xdp_hit_names[action];

    return NULL;
}

int get_ifindex(const char *raw_ifname);
int attach(int if_index, char *prog_path, char *section, uint32_t xdp_flags);
int detach(int if_index, char *prog_path, uint32_t xdp_flags);
int open_bpf_map(const char *file);
int update_map(const char *map, void *key, bool is_insert);
int update_map_key(const char *map, void *key, void *value);
int delete_map_key(const char *map, void *key);

#endif
