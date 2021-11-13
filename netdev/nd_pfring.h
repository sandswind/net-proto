#ifndef __NETDEV_PFRING_H
#define __NETDEV_PFRING_H

#include "cmn_base.h"
#include "cmn_log.h"
#include <sys/time.h>
#include <pfring.h>
#include <pcap.h>

#define DEFAULT_SNAPLEN         1600
#define DEFAULT_CHANNEL_COUNT   64
#define PCPP_MAX_PACKET_SIZE    2000

typedef void (*arrive_cb)(uint8_t *data, int data_len, struct timeval timestamp, bool is_delete);

struct if_channel
{
    bool      is_init;
    bool      is_affinity;
    pthread_t rx_td;
    pfring    *pfd;
};

struct ifdev
{
    bool                is_hw_clock;
    time_t              date;
    int32_t             mode;
    int32_t             cluster_id;
    int32_t             rx_count;
    int32_t             mtu_size;
    char                name[128];
    char                app[64];
    char                mac[8];
    struct if_channel   channels[DEFAULT_CHANNEL_COUNT];
};

#if 0

typedef enum {
  cluster_per_flow = 0,              /* 6-tuple: <src ip, src port, dst ip, dst port, proto, vlan>  */
  cluster_round_robin,
  cluster_per_flow_2_tuple,          /* 2-tuple: <src ip,           dst ip                       >  */
  cluster_per_flow_4_tuple,          /* 4-tuple: <src ip, src port, dst ip, dst port             >  */
  cluster_per_flow_5_tuple,          /* 5-tuple: <src ip, src port, dst ip, dst port, proto      >  */
  cluster_per_flow_tcp_5_tuple,      /* 5-tuple only with TCP, 2 tuple with all other protos        */
  /* same as above, computing on tunnel content when present */
  cluster_per_inner_flow,            /* 6-tuple: <src ip, src port, dst ip, dst port, proto, vlan>  */
  cluster_per_inner_flow_2_tuple,    /* 2-tuple: <src ip,           dst ip                       >  */
  cluster_per_inner_flow_4_tuple,    /* 4-tuple: <src ip, src port, dst ip, dst port             >  */
  cluster_per_inner_flow_5_tuple,    /* 5-tuple: <src ip, src port, dst ip, dst port, proto      >  */
  cluster_per_inner_flow_tcp_5_tuple,/* 5-tuple only with TCP, 2 tuple with all other protos        */
  /* new types, for L2-only protocols */
  cluster_per_flow_ip_5_tuple,       /* 5-tuple only with IP, 2 tuple with non-IP <src mac, dst mac> */
  cluster_per_inner_flow_ip_5_tuple, /* 5-tuple only with IP, 2 tuple with non-IP <src mac, dst mac> */
  cluster_per_flow_ip_with_dup_tuple /* 1-tuple: <src ip> and <dst ip> with duplication              */
} cluster_type;

#endif

static inline
cluster_type get_cluster_type()
{
    if (getenv("PF_RING_USE_CLUSTER_PER_FLOW"))
        return cluster_per_flow;
    else if (getenv("PF_RING_USE_CLUSTER_PER_FLOW_2_TUPLE"))
        return cluster_per_flow_2_tuple;
    else if (getenv("PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE"))
        return cluster_per_flow_4_tuple;
    else if (getenv("PF_RING_USE_CLUSTER_PER_FLOW_TCP_5_TUPLE"))
        return cluster_per_flow_tcp_5_tuple;
    else if (getenv("PF_RING_USE_CLUSTER_PER_FLOW_5_TUPLE"))
        return cluster_per_flow_5_tuple;
    else
        return cluster_per_flow_4_tuple; //Round robin never makes sense for bro
}

int ifdev_open_pfring(char *name, char *app, bool is_hw_clock, int mode, pfring **out);
int ifdev_close_pfring(pfring *ring);
int ifdev_set_cluster(pfring *ring, int cluster_id);
int  ifdev_recv_pfring(pfring *ring, bool is_buffer, arrive_cb cb);
bool ifdev_send_pfring(pfring *ring, uint8_t *pkg, int pkg_len);

int ifdev_open(struct ifdev *dev, uint8_t *channel_ids, int channel_count);
int ifdev_recv(struct ifdev *dev, arrive_cb cb);
int ifdev_close(struct ifdev *dev);
void ifdev_list_info();

#endif
