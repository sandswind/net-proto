#include "cmn_base.h"
#include "cmn_log.h"
#include "nd_pfring.h"
#include "net_protocol.h"
#include "net_redis.h"

void
arrive_pkg(uint8_t *data, int data_len, struct timeval timestamp, bool is_delete)
{
    int ret = 0;
    struct tm t;
    char date_time[64] = {0};
    char buf[1024] = {0};
    struct packet_context ctx;
    struct packet_meta pckt;

    memset(&ctx, 0x00, sizeof(struct packet_context));
    memset(&pckt, 0x00, sizeof(struct packet_meta));
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&timestamp.tv_sec, &t));
    log_info("gettimeofday: date_time=%s, tv_usec=%ld\n", date_time, timestamp.tv_usec);

//    loga_hexdump(data, data_len, "%d", is_delete);

    ret = packet_ingress(data, data_len, &ctx, &pckt);
    log_info("parse pkg ingress >> ret:%d", ret);

    if (pckt.flow.dport == 6379 && pckt.payload_size > 0) {
        ret = format_redis(pckt.payload, pckt.payload_size, buf, sizeof(buf));

        if (ret > 0)
            log_info("parse redis %d >> %s", ret, buf);
    }
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
