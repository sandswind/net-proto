#include "nd_pfring.h"

static int
ifdev_set_hw_clock(pfring *ring)
{
    struct timespec local = {0};

    if (clock_gettime(CLOCK_REALTIME, &local) != 0) {
        log_error("could not set pfring devices clock, clock_gettime failed, %s", strerror(errno));
        return CMN_ERROR;
    }

    if (pfring_set_device_clock(ring, &local) < 0) {
        log_error("could not set pfring devices clock, pfring_set_device_clock failed, %s", strerror(errno));
        return CMN_ERROR;
    }

    return CMN_OK;
}

int
ifdev_set_cluster(pfring *ring, int cluster_id)
{
    cluster_type mode = 0;

    if (cluster_id > 0) {
        mode = get_cluster_type();
        if (pfring_set_cluster(ring, cluster_id, mode)) {
            log_error("pfring_set_cluster error, %d:%d:%s", cluster_id, mode, strerror(errno));
            return CMN_ERROR;
        }
    }

    return CMN_OK;
}

static uint8_t
ifdev_get_rx_channels(pfring *ring, char *name)
{
    uint32_t flags = 0;
    uint8_t res = 0;
    pfring *in = ring;

    if (!in) {
        res = pfring_get_num_rx_channels(in);
        return res;
    }

    flags = PF_RING_PROMISC | PF_RING_REENTRANT | PF_RING_HW_TIMESTAMP | PF_RING_DNA_SYMMETRIC_RSS;
    in = pfring_open(name, DEFAULT_SNAPLEN, flags);
    res = pfring_get_num_rx_channels(in);
    pfring_close(in);

    return res;
}

int
ifdev_open_pfring(char *name, char *app, bool is_hw_clock, int mode, pfring **out)
{
    uint32_t flags = 0;
    pfring  *ring = NULL;
    int direction = 0;

    if (strlen(name) == 0) {
        return CMN_ERROR;
    }

//    flags = PF_RING_LONG_HEADER | PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;

    flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;

#ifdef PFRING_IXIA_TIMESTAMP
         flags |= PF_RING_IXIA_TIMESTAMP;
#elif PFRING_VSS_APCON_TIMESTAMP
         flags |= PF_RING_VSS_APCON_TIMESTAMP;
#endif

#ifdef PFRING_NO_PARSE
    flags |= PF_RING_DO_NOT_PARSE;
#endif

    if (is_hw_clock) {
        flags |= PF_RING_HW_TIMESTAMP;
    }

    ring = pfring_open(name, DEFAULT_SNAPLEN, flags);
    if (ring == NULL) {
        log_error("open pfring error, %s, %s", name, strerror(errno));
        return CMN_ERROR;
    }

    if (is_hw_clock) {
        ifdev_set_hw_clock(ring);
    }

    pfring_set_poll_watermark(ring, 8);

    if (pfring_set_application_name(ring, app) != 0) {
        pfring_close(ring);
        log_error("pfring_set_application_name error, %s, %s", name, strerror(errno));
        return CMN_ERROR;
    }

    switch(mode) {
    case 0: direction = rx_and_tx_direction; break;
    case 1: direction = rx_only_direction;   break;
    case 2: direction = tx_only_direction;   break;
    default: direction = rx_and_tx_direction; break;
    }

    if(pfring_set_direction(ring, direction) != 0) {
        log_error("pfring_set_direction error, %s, %s", name, strerror(errno));
        return CMN_ERROR;
    }

    if(mode == 1) {
        if(pfring_set_socket_mode(ring, recv_only_mode) != 0){
            log_error("pfring_set_socket_mode error, %s, %s", name, strerror(errno));
            return CMN_ERROR;
        }
    }

    if (pfring_enable_rss_rehash(ring) < 0 || pfring_enable_ring(ring) < 0) {
        pfring_close(ring);
        log_error("pfring enable error, %s, %s", name, strerror(errno));
        return CMN_ERROR;
    }
    *out = ring;

    return CMN_OK;
}

int
ifdev_close_pfring(pfring *ring)
{
    if (ring == 0){
        pfring_close(ring);
    }
    return CMN_OK;
}

int
ifdev_recv_pfring(pfring *ring, bool is_buffer, arrive_cb cb)
{
    int result = 0;
    uint8_t *buffer = NULL;
    uint32_t bufferLen = 0;
    struct pfring_pkthdr hdr;

    // in multi-threaded mode flag PF_RING_REENTRANT is set, and this flag doesn't work with zero copy
    // so I need to allocate a buffer and set buffer to point to it
    if (is_buffer) {
        uint8_t tempBuffer[PCPP_MAX_PACKET_SIZE];
        buffer = tempBuffer;
        bufferLen = PCPP_MAX_PACKET_SIZE;
    }

    result = pfring_recv(ring, &buffer, bufferLen, &hdr, 0);
    if (result > 0) {
        // if caplen < len it means we don't have the whole packet, so drop it.
        if (hdr.caplen != hdr.len){
            log_error("packet dropped due to len:%d != caplen:%d", hdr.caplen, hdr.len);
//            loga_hexdump(buffer, hdr.caplen, "packet dropped due to len:%d != caplen:%d", hdr.caplen, hdr.len);
            return CMN_ERROR;
        }

        if(hdr.ts.tv_sec == 0)
            gettimeofday(&hdr.ts, NULL);

        if (cb != NULL) {
            cb(buffer, hdr.caplen, hdr.ts, false);
        }
    } else if (result < 0) {
        log_error("pfring_recv returned an error: [errno=%d]", result);
        return CMN_ERROR;
    }

    return CMN_OK;
}

static bool
ifdev_send_data(pfring *ring, uint8_t *pkg, int pkg_len, int mtu, bool is_flush_tx)
{
    int max_tries = 5;
    int tries = 0;
    int res = 0;
    uint8_t flush_flag = 0;

    if (!ring)
    {
        log_error("Device is not opened. Cannot send packets");
        return false;
    }

    flush_flag = (is_flush_tx? 1 : 0);
    while (tries < max_tries) {
        if (pkg_len > mtu)
            pkg_len = mtu;

        res = pfring_send(ring, (char*)pkg, pkg_len, flush_flag);

        // res == -1 means it's an error coming from "sendto" which is the Linux API PF_RING is using to send packets
        // errno == ENOBUFS means write buffer is full. PF_RING driver expects the userspace to handle this case
        // My implementation is to sleep for 10 usec and try again
        if (res == -1 && errno == ENOBUFS) {
            tries++;
            loga("try #%d: Got ENOBUFS (write buffer full) error while sending packet. Sleeping 20 usec and trying again", tries);
            usleep(2000);
        } else {
            break;
        }
    }

    if (tries >= max_tries) {
        log_error("tried to send data %d times but write buffer is full", max_tries);
        return false;
    }

    if (res < 0) {
        // res == -1 means it's an error coming from "sendto" which is the Linux API PF_RING is using to send packets
        if (res == -1)
            log_error("error sending packet: Linux errno: %s [%d]", strerror(errno), errno);
        else
            log_error("error sending packet: pfring_send returned an error: %d , errno: %s [%d]", res, strerror(errno), errno);

        return false;
    } else if (res != pkg_len) {
        log_error("couldn't send all bytes, only %d bytes out of %d bytes were sent", res, pkg_len);
        return false;
    }

    return true;
}

bool
ifdev_send_pfring(pfring *ring, uint8_t *pkg, int pkg_len)
{
    return ifdev_send_data(ring, pkg, pkg_len, 1600, true);
}

static int
ifdev_calc_version(pfring *ring, char *out, int32_t out_size)
{
    uint32_t version = 0;

    if (pfring_version(ring, &version) < 0) {
        log_error("couldn't retrieve PF_RING version, pfring_version returned an error");
        return CMN_ERROR;
    }

    snprintf(out, out_size, "PF_RING v.%d.%d.%d\n",
        (version & 0xFFFF0000) >> 16,
        (version & 0x0000FF00) >> 8,
        version & 0x000000FF);

    loga("PF_RING version is: %s", out);


    if (version != RING_VERSION_NUM) {
        log_error("PF_RING version mismatch (expected v.%d.%d.%d found v.%d.%d.%d)",
        (RING_VERSION_NUM & 0xFFFF0000) >> 16, (RING_VERSION_NUM & 0x0000FF00) >> 8, RING_VERSION_NUM & 0x000000FF,
        (version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8, version & 0x000000FF);
        return CMN_ERROR;
    }

    return CMN_OK;
}

void
ifdev_list_info()
{
    int err = 0;
    uint32_t flags = 0;
    char buf[256] = {0};
    uint8_t mac_address[6] = {0};
    pcap_if_t *if_list = NULL;
    pcap_if_t *if_current = NULL;
    pfring *ring = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char version[128] = {0};
    FILE *fd = popen("lsmod | grep pf_ring", "r");

    if (fread (buf, 1, sizeof (buf), fd) <= 0) {
        log_error("pf_ring kernel module isn't loaded. Please run: 'sudo insmod <PF_RING_LOCATION>/kernel/pf_ring.ko'");
        fclose(fd);
        return;
    }
    fclose(fd);
    loga("pf_ring kernel module is loaded, %s", buf);

    err = pcap_findalldevs(&if_list, errbuf);
    if (err < 0) {
        log_error("failed to search devices: %s", errbuf);
        return;
    }

    if_current = if_list;
    while (if_current != NULL) {
        if ((if_current->flags & 0x1) != PCAP_IF_LOOPBACK) {
            flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;
            ring = pfring_open(if_current->name, 128, flags);
            if (ring != NULL) {
                if (strlen(version) == 0) {
                    ifdev_calc_version(ring, version, 128);
                }

                loga("found interface: %s", if_current->name);

                // rx channels
                uint8_t res = pfring_get_num_rx_channels(ring);
                loga("found interface: %s -> rx_channels %d", if_current->name, res);

                // get device MAC address
                if (pfring_get_bound_device_address(ring, mac_address) < 0) {
                    log_error("Unable to read the device MAC address for interface '%s'", if_current->name);
                }
                snprintf(buf, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned char)mac_address[0],
                    (unsigned char)mac_address[1],
                    (unsigned char)mac_address[2],
                    (unsigned char)mac_address[3],
                    (unsigned char)mac_address[4],
                    (unsigned char)mac_address[5]);
                loga("found interface: %s -> mac %s", if_current->name, buf);

                int mtu = pfring_get_mtu_size(ring);
                loga("interface: %s -> mtu %d", if_current->name, mtu);

                pfring_close(ring);
            }
        }
        if_current = if_current->next;
    }
}


static int
ifdev_init(struct ifdev *dev)
{
    uint8_t  res = 0;
    uint32_t flags = 0;
    int      mtu = 0;
    pfring  *ring = NULL;
    uint8_t  mac_address[6] = {0};
    char    sbuf[32] = {0};

    flags = PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS;
    ring = pfring_open(dev->name, DEFAULT_SNAPLEN, flags);
    if (ring != NULL) {
        // rx channels
        res = pfring_get_num_rx_channels(ring);
        dev->rx_count = res;
        loga("interface: %s -> rx channels %d", dev->name, res);

        // get device MAC address
        if (pfring_get_bound_device_address(ring, mac_address) < 0) {
            log_error("Unable to read the device MAC address for interface '%s'", dev->name);
            return CMN_ERROR;
        }
        memcpy((char *)dev->mac, (char *)mac_address, 6);
        snprintf(sbuf, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)mac_address[0],
            (unsigned char)mac_address[1],
            (unsigned char)mac_address[2],
            (unsigned char)mac_address[3],
            (unsigned char)mac_address[4],
            (unsigned char)mac_address[5]);
        loga("found interface: %s -> mac %s", dev->name, sbuf);

        mtu = pfring_get_mtu_size(ring);
        loga("interface: %s -> mtu %d", dev->name, mtu);
        dev->mtu_size = mtu + 14 + 4;
        pfring_close(ring);
    }
    
    return CMN_OK;
}

int
ifdev_open(struct ifdev *dev, uint8_t *channel_ids, int channel_count)
{
    bool is_opened = false;
    int res = 0;
    uint8_t total = 0;
    uint8_t chan_id = 0;
    char    sbuf[256] = {0};
    struct if_channel *channel = NULL;

    if (!dev) {
        return CMN_ERROR;
    }

    if (dev->rx_count > 0) {
        return CMN_OK;
    }

    ifdev_init(dev);

    total = dev->rx_count;
    log_info("get rx_channels is %d", total);

    for (int i = 0; i < channel_count; i++) {
        chan_id = channel_ids[i];
        if (chan_id > total) {
            log_error("Trying to open the device with a RX channel that doesn't exist. Total RX channels are [%d], tried to open channel [%d]", total, chan_id);
            return false;
        }
    }
    dev->rx_count = 0;

    for (int i = 0; i < channel_count; i++) {
        is_opened = false;
        chan_id = channel_ids[i];
        channel = &dev->channels[i];
        snprintf(sbuf, sizeof(sbuf), "%s@%d", dev->name, chan_id);

        loga("trying to open device [%s] on channel [%d]. channel name [%s]", dev->name, chan_id, sbuf);
        res = ifdev_open_pfring(sbuf, dev->app, false, dev->mode, &channel->pfd);
        switch(res) {
        case 1:
            log_error("couldn't open a ring on channel [%d] for device [%s]", chan_id, dev->name);
            break;
        case 2:
            log_error("unable to enable ring on channel [%d] for device [%s]", chan_id, dev->name);
            break;
        case 0:
            loga("succeeded opening device [%s] on channel [%d]. channel name [%s]", dev->name, chan_id, sbuf);
            dev->rx_count++;
            is_opened = true;
            break;
        }

        if (!is_opened)
            break;

        channel->is_init = true;
    }

    if (dev->rx_count < channel_count) {
        for (int i = 0; i < dev->rx_count-1; i++) {
            channel = &dev->channels[i];
            if (channel->is_init)
                pfring_close(channel->pfd);
        }
        dev->rx_count = 0;
        return CMN_ERROR;
    }

    return CMN_OK;
}

int
ifdev_recv(struct ifdev *dev, arrive_cb cb)
{
    int ret = 0;
    struct if_channel *chan = NULL;

    if (dev->rx_count == 0)
        return CMN_ERROR;

    for (int i = 0; i < dev->rx_count; i++){
        chan = &dev->channels[i];
        ret = ifdev_recv_pfring(chan->pfd, false, cb);
        if (ret == 0) {
            continue;
        } else {
            return ret;
        }
    }
    return CMN_OK;
}

int
ifdev_close(struct ifdev *dev)
{
    struct if_channel *chan = NULL;

    if (dev->rx_count == 0)
        return CMN_OK;

    for (int i = 0; i < dev->rx_count; i++){
        chan = &dev->channels[i];
        pfring_close(chan->pfd);
    }

    dev->rx_count = 0;
    return CMN_OK;
}

