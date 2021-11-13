#ifndef __NET_PROTOCOL_H
#define __NET_PROTOCOL_H

#include "net.h"

#define PCKT_MAX_SIZE   65536

#define IPV4_HDR_LEN_NO_OPT 20
#define IPV4_PLUS_ICMP_HDR  28


// FLAGS:
#define F_ICMP (1 << 0)
#define F_SYN_SET (1 << 1)
#define F_PSH_SET (1 << 2)
#define F_FIN_SET (1 << 3)
#define F_RST_SET (1 << 4)

// default value: 1500 ip size + 14 ether hdr size
#ifndef MAX_PCKT_SIZE
#define MAX_PCKT_SIZE 1514
#endif

#define IP_DONT_FRAGMENT  0x40
#define IP_MORE_FRAGMENTS 0x20

#define ICMP_TOOBIG_SIZE 65536
#define ICMP_TOOBIG_PAYLOAD_SIZE (ICMP_TOOBIG_SIZE - 6)

#define ICMP_ECHOREPLY      0   /* Echo Reply           */
#define ICMP_DEST_UNREACH   3   /* Destination Unreachable  */
#define ICMP_SOURCE_QUENCH  4   /* Source Quench        */
#define ICMP_REDIRECT       5   /* Redirect (change route)  */
#define ICMP_ECHO           8   /* Echo Request         */
#define ICMP_TIME_EXCEEDED  11  /* Time Exceeded        */
#define ICMP_PARAMETERPROB  12  /* Parameter Problem        */
#define ICMP_TIMESTAMP      13  /* Timestamp Request        */
#define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply      */
#define ICMP_INFO_REQUEST   15  /* Information Request      */
#define ICMP_INFO_REPLY     16  /* Information Reply        */
#define ICMP_ADDRESS        17  /* Address Mask Request     */
#define ICMP_ADDRESSREPLY   18  /* Address Mask Reply       */
#define NR_ICMP_TYPES       18


#define ACTION_PROCESSING 0
#define ACTION_FORMAT     1
#define ACTION_DROP       2
#define ACTION_TX         4
#define ACTION_FRAGMENT   6

#ifndef ACTION_MAX
#define ACTION_MAX (ACTION_EVENT + 1)
#endif



/*
 * packet layer:

      |Eth       |IPv4       |TCP       |Packet          |
      |Header    |Header     |Header    |Payload         |


      |--------------------------------------------------|
      EthLayer data
                 |---------------------------------------|
                 IPv4Layer data
                             |---------------------------|
                             TcpLayer data
                                        |----------------|
                                        PayloadLayer data

*/

#pragma pack(push,1)

// Ethernet header
struct eth_hdr {
    uint8_t   eth_dest[ETH_ALEN];
    uint8_t   eth_source[ETH_ALEN];
    uint16_t eth_proto;
};

// IPv4 header
struct iphdr {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// TCP header
struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    union {
        struct {
            // Field order has been converted LittleEndiand -> BigEndian
            // in order to simplify flag checking (no need to ntohs())
            uint16_t ns : 1,
            reserved : 3,
            doff : 4,
            fin : 1,
            syn : 1,
            rst : 1,
            psh : 1,
            ack : 1,
            urg : 1,
            ece : 1,
            cwr : 1;
        };
    };
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct udphdr {
   uint16_t   source;
   uint16_t   dest;
   uint16_t   len;
   uint16_t   check;
};

struct icmphdr {
  uint8_t   type;
  uint8_t   code;
  uint16_t  checksum;
  union {
    struct {
        uint16_t  id;
        uint16_t  sequence;
    } echo;
    uint32_t  gateway;
    struct {
        uint16_t  __unused;
        uint16_t  mtu;
    } frag;
  } un;
};

#pragma pack(pop)



static inline bool parse_eth_frame(struct eth_hdr *eth, uint32_t size, struct packet_context *ctx)
{
    uint16_t eth_type = 0;
    uint16_t offset = 0;

    offset = sizeof(*eth);
    if (offset > size) {
        return false;
    }
    eth_type = eth->eth_proto;

    log_debug("Debug: eth_type:0x%x, pkg_size:%d\n", ntohs(eth_type), size);

    ctx->hdr_proto = ntohs(eth_type); /* Convert to host-byte-order */
    ctx->hdr_size += offset;
    ctx->payload_len -= offset;
    ctx->ptr = (char *)ctx->data_start + ctx->hdr_size;

    return true;
}

static inline int parse_pkt_to_ctx(void *pkt, uint32_t size, struct packet_context *ctx)
{
    if (ctx != NULL) {
        ctx->data_start = (void *)pkt;
        ctx->data_end = (void *)pkt +size;
        ctx->hdr_proto = 0;
        ctx->hdr_size = 0;
        ctx->payload_len = size;
        ctx->length = size;

        if (!parse_eth_frame(pkt, size, ctx)) {
            return ACTION_FORMAT;
        }
    }

    return ACTION_PROCESSING;
}

static inline uint64_t calc_offset(bool is_icmp)
{
    uint64_t offset = sizeof(struct eth_hdr);

    offset += sizeof(struct iphdr);
    if (is_icmp) {
        offset += (sizeof(struct icmphdr) + sizeof(struct iphdr));
    }

    return offset;
}

static inline uint16_t csum_fold_helper(uint64_t csum) {
    int i;
    for (i = 0; i < 4; i ++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static inline void ipv4_csum_inline(void *iph, uint64_t *csum) {
    uint16_t *next_iph_u16 = (uint16_t *)iph;
    for (int i = 0; i < (int)(sizeof(struct iphdr)) >> 1; i++) {
        *csum += *next_iph_u16++;
    }
    *csum = csum_fold_helper(*csum);
}

static inline uint8_t get_fragment_flags(struct iphdr *hdr)
{
    return hdr->frag_off & 0xE0;
}

static inline uint16_t get_fragment_offset(struct iphdr *hdr)
{
    return be16toh(hdr->frag_off & (uint16_t)0xFF1F) * 8;
}

static inline bool is_fragment(struct iphdr *hdr)
{
    return ((get_fragment_flags(hdr) & IP_MORE_FRAGMENTS) != 0 || get_fragment_offset(hdr) != 0);
}

static inline bool is_first_fragment(struct iphdr *hdr)
{
    return is_fragment(hdr) && (get_fragment_offset(hdr) == 0);
}

static inline bool is_last_fragment(struct iphdr *hdr)
{
    return is_fragment(hdr) && ((get_fragment_flags(hdr) & IP_MORE_FRAGMENTS) == 0);
}


static inline bool parse_udp(struct packet_context *ctx, struct packet_meta *pckt)
{
    uint32_t udp_len = 0;
    uint32_t now_len = ctx->payload_len;
    struct udphdr *udp = (struct udphdr *)ctx->ptr;
    void *data = ctx->ptr;
    void *data_end = ctx->data_end;

    if (data + sizeof(struct udphdr) > data_end) {
       return false;
    }

    pckt->flow.sport = ntohs(udp->source);
    pckt->flow.dport = ntohs(udp->dest);

    now_len -= sizeof(struct udphdr);
    udp_len = ntohs(udp->len);
    ctx->ptr = (char *)data + sizeof(struct udphdr);
    ctx->payload_len = udp_len > now_len ? now_len : udp_len;
    ctx->hdr_size += sizeof(struct udphdr);

    log_info("-----size---[%d:%d]-----", now_len, udp_len);
    
    pckt->payload_size = ctx->payload_len;
    pckt->payload = ctx->ptr;

    return true;
}

static inline bool parse_tcp(struct packet_context *ctx, struct packet_meta *pckt)
{
    uint32_t tcphdr_len = 0;
    uint32_t now_len = ctx->payload_len;
    struct tcphdr *tcp = (struct tcphdr *)ctx->ptr;
    void *data = ctx->ptr;
    void *data_end = ctx->data_end;

    if (data + sizeof(struct tcphdr) > data_end) {
        return false;
    }

    if (tcp->syn) {
        log_info("tcp syn");
        pckt->flags |= F_SYN_SET;
    }

    if (tcp->psh) {
        log_info("tcp psh");
        pckt->flags |= F_PSH_SET;
    }

    if (tcp->fin) {
        log_info("tcp fin");
        pckt->flags |= F_FIN_SET;
    }

    if (tcp->rst) {
        log_info("tcp rst");
        pckt->flags |= F_RST_SET;
    }


    pckt->flow.sport = ntohs(tcp->source);
    pckt->flow.dport = ntohs(tcp->dest);
    pckt->flow.window = ntohs(tcp->window);
    pckt->flow.seq = htonl(tcp->seq);
    pckt->flow.ack = htonl(tcp->ack_seq);

    
    tcphdr_len = tcp->doff * 4;
    now_len -= tcphdr_len;
    ctx->ptr = (char *)data + tcphdr_len;
    //ctx->payload_len = tcphdr_len > now_len ? now_len : tcphdr_len;
    ctx->payload_len = now_len ;
    ctx->hdr_size += tcphdr_len;

    log_info("-----size---[%d:%d]-----", now_len, tcphdr_len);
    pckt->payload_size = ctx->payload_len;
    pckt->payload = ctx->ptr;

    return true;
}


static inline int swap_mac_and_send(void *data, void *data_end)
{
    struct eth_hdr *eth = (struct eth_hdr *)data;
    unsigned char tmp_mac[ETH_ALEN] = {0};

    memcpy(tmp_mac, eth->eth_source, ETH_ALEN);
    memcpy(eth->eth_source, eth->eth_dest , ETH_ALEN);
    memcpy(eth->eth_dest, tmp_mac, ETH_ALEN);

    return ACTION_TX;
}

static inline void swap_mac(void *data, struct eth_hdr *orig_eth)
{
    struct eth_hdr *eth = NULL;
    eth = data;

    memcpy(eth->eth_source, orig_eth->eth_dest , ETH_ALEN);
    memcpy(eth->eth_dest, orig_eth->eth_source, ETH_ALEN);
    eth->eth_proto = orig_eth->eth_proto;
}

static inline int send_icmp_reply(struct packet_context *ctx)
{
    uint32_t tmp_addr = 0;
    uint64_t csum = 0;
    uint64_t offset = 0;
    void *data = ctx->data_start;
    void *data_end = ctx->data_end;
    struct iphdr *iph = (struct iphdr *)data + sizeof(struct eth_hdr);
    struct icmphdr *icmp_hdr = (struct icmphdr *)ctx->ptr;

    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->checksum += 0x0008;
    iph->ttl = DEFAULT_TTL;
    tmp_addr = iph->daddr;
    iph->daddr = iph->saddr;
    iph->saddr = tmp_addr;
    iph->check = 0;
    ipv4_csum_inline(iph, &csum);
    iph->check = csum;

    return swap_mac_and_send(data, data_end);
}

static inline int parse_icmp(struct packet_context *ctx, struct packet_meta *pckt)
{
    uint32_t now_len = ctx->payload_len;
    struct icmphdr *icmp_hdr = (struct icmphdr *)ctx->ptr;
    void *data = ctx->ptr;
    void *data_end = ctx->data_end;

    if ((data + sizeof(struct icmphdr)) > data_end) {
        return ACTION_DROP;
    }

    pckt->flags |= F_ICMP;

    if (icmp_hdr->type == ICMP_ECHO) {
//        return send_icmp_reply(data, data_end);
        log_info("icmp echo");
//        return ACTION_TX;
    }

    if (icmp_hdr->type != ICMP_DEST_UNREACH) {
        return ACTION_PROCESSING;
    }

    now_len -= sizeof(struct icmphdr);
    ctx->ptr = (char *)data + sizeof(struct icmphdr);
    ctx->payload_len = now_len;
    ctx->hdr_size += sizeof(struct icmphdr);

    pckt->payload_size = ctx->payload_len;
    pckt->payload = ctx->ptr;

    return ACTION_PROCESSING;
}

int
process_headers(struct packet_meta *pckt, uint8_t *protocol, uint16_t *pkt_bytes, struct packet_context *ctx);

int
packet_ingress(void *ptr, uint32_t len, struct packet_context *ctx, struct packet_meta *pckt);

#endif
