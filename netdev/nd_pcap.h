#ifndef __NETDEV_PCAP_H
#define __NETDEV_PCAP_H

#include "cmn_base.h"
#include "cmn_log.h"
#include <pcap.h>

#define MAX_PCAP_ERRORS_BEFORE_BAIL 5

typedef void (*arrive_cb)(uint8_t *data, int data_len, struct timeval timestamp, bool is_delete);

struct pcapdev
{
    bool is_debug;
    bool is_file;
    int  promisc;
    int  snap_len;
    int  buf_size;
    int  timeout;
    int  offset;
    int  count;
    char if_name[256];
    char filter[256];
    pcap_t *pcap;
    arrive_cb cb;
};

int pcapdev_open(struct pcapdev *dev, bool is_in);
int pcapdev_close(struct pcapdev *dev);
int pcapdev_run(struct pcapdev *dev);
int pcapdev_recv(struct pcapdev *dev, arrive_cb cb);
void pcapdev_stop(struct pcapdev *dev);
void pcapdev_list_info();

#endif
