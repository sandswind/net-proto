#include "cmn_base.h"
#include "cmn_log.h"
#include "nd_pfring.h"
#include "layer_pkg.h"

void
arrive_pkg(uint8_t *data, int data_len, struct timeval timestamp, bool is_delete)
{
    struct tm t;
    char date_time[64];
    struct pkg_info info;
    int opcode = OP_ETHER_PARSE|OP_IPV4_PARSE|OP_ARP_PARSE|OP_TCP_PARSE|OP_UDP_PARSE|OP_ICMP_PARSE;

    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&timestamp.tv_sec, &t));
    log_info("gettimeofday: date_time=%s, tv_usec=%ld\n", date_time, timestamp.tv_usec);

    loga_hexdump(data, data_len, "%d", is_delete);


    pkg_parse(data, data_len, &info, opcode);

    log_info("%d:%d:%d", info.payload_size, info.fragment_flag, info.data_flag);
    log_info("%d >> %d:%d:%d:%d", info.proto, info.tuple.src, info.tuple.src, info.tuple.dport, info.tuple.sport);
}


int
main(int argc, char **argv)
{
    int code = 1;
    int ret = 0;
    struct ifdev dev;
    pfring *ring = NULL;
    uint8_t *channel_ids = malloc(sizeof(char)*8);

    if (log_open(LOG_DEBUG, "console") != CMN_OK) {
        printf("init log error\n");
        exit(code);
    }

    ifdev_list_info();

    memset(&dev, 0x00, sizeof(struct ifdev));
    strcpy(dev.name, argv[1]);
    strcpy(dev.app, "testv");
    dev.mode = 1;

    channel_ids[0] = 1;
    ret = ifdev_open_pfring(dev.name, dev.app, false, 1, &ring);
    log_info("open %d", ret);

    while(1){
        ifdev_recv_pfring(ring, true, arrive_pkg);
        usleep(100000);
    }

    ret = ifdev_close_ring(ring);
    log_info("close %d", ret);

    log_close();
    exit(code);
}
