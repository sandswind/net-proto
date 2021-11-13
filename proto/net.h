#ifndef __NET_H
#define __NET_H

#include "cmn.h"
#include "cmn_base.h"
#include "cmn_log.h"

#define NETP_IFNAME_LEN     256
#define NETP_IPPROTO_ICMP 1
#define NETP_IPPROTO_IP   0
#define NETP_IPPROTO_RAW  255
#define NETP_IPPROTO_TCP  6
#define NETP_IPPROTO_UDP  17

#ifndef DEFAULT_TTL
#define DEFAULT_TTL 55
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* Ethernet protocol ID's */
#define NETP_ETHERTYPE_8021Q    0x8100     /** VLAN */
#define NETP_ETHERTYPE_8021AD   0x88A8     /** VLAN */
#define NETP_ETHERTYPE_IP       0x0800     /** IP */
#define NETP_ETHERTYPE_ARP      0x0806     /** Address resolution */
#define NETP_ETHERTYPE_REVARP   0x8035     /** Reverse ARP */
#define NETP_ETHERTYPE_AT       0x809B     /** AppleTalk protocol */
#define NETP_ETHERTYPE_AARP     0x80F3     /** AppleTalk ARP */
#define NETP_ETHERTYPE_VLAN     0x8100     /** IEEE 802.1Q VLAN tagging */
#define NETP_ETHERTYPE_IPX      0x8137     /** IPX */
#define NETP_ETHERTYPE_IPV6     0x86dd     /** IP protocol version 6 */
#define NETP_ETHERTYPE_LOOPBACK 0x9000     /** used to test interfaces */
#define NETP_ETHERTYPE_PPPOED   0x8863     /** PPPoE discovery */
#define NETP_ETHERTYPE_PPPOES   0x8864     /** PPPoE session */
#define NETP_ETHERTYPE_MPLS     0x8847     /** MPLS */
#define NETP_ETHERTYPE_PPP      0x880B     /** Point-to-point protocol (PPP) */

#define GET_UINT8(D,O)   (*(uint8_t  *)((&(((uint8_t *)D)[O]))))
#define GET_UINT16(D,O)  (*(uint16_t *)((&(((uint8_t *)D)[O]))))
#define GET_UINT32(D,O)  (*(uint32_t *)((&(((uint8_t *)D)[O]))))
#define GET_UINT64(D,O)  (*(uint64_t *)((&(((uint8_t *)D)[O]))))

#define NET_OK      (0)
#define NET_EFORMAT (9103)
#define NET_EFRAGMENT (9104)
#define NET_EICMP   (9105)
#define NET_EDROP   (9106)


#define NET_EFORMAT_HTTP (9201)
#define NET_EFORMAT_TLS  (9301)

#define NET_TLS_NO_SNI       (9302)
#define NET_TLS_NO_HANDSHAKE (9303)
#define NET_TLS_NO_CLIENTHELLO (9304)

struct packet_context
{
    uint32_t length;
    uint32_t payload_len;
    uint16_t hdr_proto;
    uint16_t hdr_size;
    void *data_start;
    void *data_end;
    void *ptr;

};

// key metadata
struct packet_key {
    uint32_t src;
    uint32_t dst;
    uint16_t sport;
    uint16_t dport;
    uint16_t proto;
    uint16_t window;
    uint32_t seq;
    uint32_t ack;
};

// client's packet metadata
struct packet_meta {
    uint32_t pkg_size;
    uint32_t fragment;  // 1-true, 2-first, 4-middle, 8-last
    uint32_t flags;
    int32_t  payload_size;
    struct   packet_key flow;
    void     *payload;
};


#endif
