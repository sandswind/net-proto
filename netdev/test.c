#include "cmn_base.h"
#include "cmn_log.h"
#include "nd_pcap.h"
#include "net_protocol.h"
#include "net_tls.h"
#include "net_http.h"

void
arrive_pkg(uint8_t *data, int data_len, struct timeval timestamp, bool is_delete)
{
    int ret = 0;
    struct tm t;
    char date_time[64] = {0};
    char buf[1024] = {0};
    char out[256] = {0};
    struct packet_context ctx;
    struct packet_meta pckt;

    memset(&ctx, 0x00, sizeof(struct packet_context));
    memset(&pckt, 0x00, sizeof(struct packet_meta));
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&timestamp.tv_sec, &t));
    log_info("gettimeofday: date_time=%s, tv_usec=%ld\n", date_time, timestamp.tv_usec);

//    loga_hexdump(data, data_len, "%d", is_delete);

    ret = packet_ingress(data, data_len, &ctx, &pckt);
    log_info("parse pkg ingress >> ret:%d", ret);

    if (pckt.payload_size == 0)
        return;

    if (pckt.flow.dport == 443) {
        ret = parse_tls_message(pckt.payload, pckt.payload_size);
        if (ret != 0)
            log_info("parse tls message error,  %d", ret);

        ret = parse_tls_sni_name(pckt.payload, pckt.payload_size, (uint8_t *)out, 256);
        if (ret == 0)
            log_info("parse tls sni[%s]", out);
        
    }  else  if (pckt.flow.dport == 80) {
        ret = http_parse_request_first_line((char *)pckt.payload, pckt.payload_size);
        if (ret > 0)
            log_info("parse http host error, %d", ret);
        
        ret = http_parse_request_host((char *)pckt.payload, pckt.payload_size, out, 256);
        if (ret == 0)
            log_info("parse http host[%s]", out);
    }
}


int
main(int argc, char **argv)
{
    int code = 1;
    int ret = 0;
    struct pcapdev dev;

    if (log_open(LOG_DEBUG, "console") != CMN_OK) {
        printf("init log error\n");
        exit(code);
    }

    pcapdev_list_info();

    memset(&dev, 0x00, sizeof(struct pcapdev));
    strcpy(dev.if_name, argv[1]);
    // dev.arrive_cb = arrive_pkg;
    dev.is_debug = true;
    dev.is_file = true;
    dev.snap_len = 65536;
    dev.buf_size = 65536*1024;
    dev.timeout  = 100;

    ret = pcapdev_open(&dev, false);
    log_info("open %d", ret);

    while(1){
        pcapdev_recv(&dev, arrive_pkg);
        usleep(100000);
    }

    ret = pcapdev_close(&dev);
    log_info("close %d", ret);

    log_close();
    exit(code);
}
