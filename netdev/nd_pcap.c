#include "nd_pcap.h"

int
pcapdev_open(struct pcapdev *dev, bool is_in)
{
    int    set_direction = 1;
    char   emsg[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *pcap = NULL;
    struct bpf_program bpfs;

    if (dev->is_file) {
        pcap = pcap_open_offline(dev->if_name, emsg);
    } else {
        pcap = pcap_open_live(dev->if_name, dev->snap_len, dev->promisc, dev->timeout, emsg);
    }

    if (!pcap) {
        log_error("create pcap error, %s %s", dev->if_name, emsg);
        goto err;
    }
    log_info("pcap open device %s success", dev->if_name);
    
    // pcap filters
    if (!dev->is_file && strlen(dev->filter) > 0) {
        memset(&bpfs, 0x00, sizeof(struct bpf_program));
        if(pcap_compile(pcap, &bpfs, dev->filter, 1, 0) == -1) {
            log_error("error compiling pcap filter: %s", pcap_geterr(pcap));
            goto err;
        }

        if(pcap_setfilter(pcap, &bpfs) == -1) {
            log_error("error setting pcap filter: %s", pcap_geterr(pcap));
            goto err;
        }

        log_info(LOG_INFO, "PCAP filter is: '%s'", dev->filter);
        pcap_freecode(&bpfs);
    }

    switch(pcap_datalink(pcap)) {
        case DLT_EN10MB:
            dev->offset = 14;
            break;
#if defined(__linux__)
        case DLT_LINUX_SLL:
            dev->offset = 16;
            break;
#elif defined(__OpenBSD__)
        case DLT_LOOP:
            set_direction = 0;
            dev->offset = 4;
            break;
#endif
        case DLT_NULL:
            set_direction = 0;
            dev->offset = 4;
            break;
        default:
            dev->offset = 0;
            break;
    }

    if ((set_direction == 1) && !dev->is_file && is_in) {
        if (pcap_setdirection(pcap, PCAP_D_IN) < 0) {
            log_error("pcap_setdirection error, %s %s", dev->if_name, pcap_geterr(pcap));
            goto err; 
        }
    }

    if(!dev->is_file) {
        if (pcap_set_tstamp_type(pcap, PCAP_TSTAMP_ADAPTER) < 0) {
            log_error("pcap_setnonblock error, %s %s", dev->if_name, pcap_geterr(pcap));
            goto err; 
        }

        if (dev->buf_size > 0) {
            if (pcap_set_buffer_size(pcap, dev->buf_size) < 0) {
                log_error("pcap_set_buffer_size error, %s %s", dev->if_name, pcap_geterr(pcap));
                goto err; 
            }
        }

        if (pcap_setnonblock(pcap, 1, emsg) < 0) {
            log_error("pcap_setnonblock error, %s %s", dev->if_name, emsg);
            goto err; 
        }
    }

    dev->pcap = pcap;
    return CMN_OK;

err:
    pcapdev_close(dev);
    return CMN_ERROR;
}

int 
pcapdev_close(struct pcapdev *dev)
{
    if (dev == NULL) {
        return CMN_ERROR;
    }
    
    if (dev->pcap != NULL) {
        pcap_close(dev->pcap);
        dev->pcap = NULL;
    }
    
    return CMN_OK;
}

static void 
packet_handler(void *user, struct pcap_pkthdr *header, unsigned char *packet)
{
    struct pcapdev *dev = (struct pcapdev *) user;
    int  offset = dev->offset;
    uint32_t pkg_size = header->len;
    uint32_t payload_size = header->caplen;

    if (dev->is_debug) {
        log_debug("handle packet, offset:%d %u:%u data ptr %p", offset, pkg_size, payload_size, packet);
    }

    if(header->ts.tv_sec == 0)
        gettimeofday(&header->ts, NULL);

    if (dev->cb != NULL) {
        dev->cb((uint8_t *)packet, payload_size, header->ts, false);
    }
}

int
pcapdev_run(struct pcapdev *dev)
{
    int ret = CMN_OK;
    int res = 0;
    uint32_t pkg_size = 0;
    uint32_t  pcap_errcnt = 0;

    while (1) {
        res = pcap_dispatch(dev->pcap, dev->count, (pcap_handler)&packet_handler, (unsigned char *)dev);
        if(res > 0) {
            if(dev->is_debug){
                log_debug("pcap_dispatch() processed: %d packets", res);
            }

            // Count the set of processed packets (pcap_dispatch() return value)
            pkg_size += res;

        } else if(res == -1) {
            // If there was an error, complain and go on (to an extent before giving up).
            log_error("[*] Error from pcap_dispatch: %s", pcap_geterr(dev->pcap));
            
            if(pcap_errcnt++ > MAX_PCAP_ERRORS_BEFORE_BAIL)  {
                log_error("[*] pcap_dispatch() %u consecutive pcap errors. quit now", pcap_errcnt);
                ret = CMN_ERROR;
                break;
            }

        } else if(res == -2) {
            /* pcap_breakloop was called, so we bail. */
            log_warn("gracefully leaving pcap_dispatch() loop, %d:%d:%d", res, pcap_errcnt, pkg_size);
            break;

        } else {
            pcap_errcnt = 0;
        }
    }
    log_warn("pcap device [%s] is out of loop, %u:%u:%d", dev->if_name, pcap_errcnt, pkg_size, ret);
    return ret;
}

int
pcapdev_recv(struct pcapdev *dev, arrive_cb cb)
{
    int ret = CMN_OK;
    int res = 0;

    if (cb != NULL) {
        dev->cb = cb;
    }

    res = pcap_dispatch(dev->pcap, dev->count, (pcap_handler)&packet_handler, (unsigned char *)dev);
    if(res > 0) {
        if(dev->is_debug){
            log_debug("pcap_dispatch() processed: %d packets", res);
        }
        // Count the set of processed packets (pcap_dispatch() return value)
        ret = res;

    } else if(res == -1) {
        // If there was an error, complain and go on (to an extent before giving up).
        log_error("[*] Error from pcap_dispatch: %s", pcap_geterr(dev->pcap));
        ret = CMN_ERROR;

    } else if(res == -2) {
        /* pcap_breakloop was called, so we bail. */
        log_warn("gracefully leaving pcap_dispatch() loop, %d", res);
    }
  
    return ret;
}

void
pcapdev_stop(struct pcapdev *dev)
{
    pcap_breakloop(dev->pcap);
}

void
pcapdev_list_info()
{
    int err = 0;
    char buf[256] = {0};
    uint8_t mac_address[6] = {0};
    pcap_if_t *if_list = NULL;
    pcap_if_t *if_current = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    err = pcap_findalldevs(&if_list, errbuf);
    if (err < 0) {
        log_error("failed to search devices: %s", errbuf);
        return;
    }

    if_current = if_list;
    while (if_current != NULL) {
        if ((if_current->flags & 0x1) != PCAP_IF_LOOPBACK) {    
            loga("found interface: %s", if_current->name);

            snprintf(buf, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)mac_address[0],
                (unsigned char)mac_address[1],
                (unsigned char)mac_address[2],
                (unsigned char)mac_address[3],
                (unsigned char)mac_address[4],
                (unsigned char)mac_address[5]);
            loga("found interface: %s -> mac %s", if_current->name, buf);
        }
        if_current = if_current->next;
    }
}

