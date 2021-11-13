#include "cmn_log.h"
#include "cmn_base.h"

#include "net_utils.h"
#include "net_protocol.h"

#define IP_HL(ip) (((ip)->ihl) & 0x0f)

int
process_headers(struct packet_meta *pckt, uint8_t *protocol, uint16_t *pkt_bytes, struct packet_context *ctx)
{
    int action = ACTION_DROP;
    void *data = ctx->ptr;
    void *data_end = ctx->data_end;
    struct iphdr *iph = (struct iphdr *)ctx->ptr;

    if (data + sizeof(struct iphdr) > data_end) {
        return ACTION_DROP;
    }

    if (iph->ihl != 5) {
        log_error("ipv4 hdr is not equal to 20bytes, %d", iph->ihl);
        return ACTION_FORMAT;
    }

    *protocol = iph->protocol;
    pckt->flow.proto = iph->protocol;
    *pkt_bytes = ntohs(iph->tot_len);
    pckt->flow.src = iph->saddr;
    pckt->flow.dst = iph->daddr;

    ctx->hdr_size += iph->ihl * 4;
    ctx->ptr = (char *)data + iph->ihl * 4;
    ctx->payload_len -= iph->ihl * 4;

    if (is_fragment(iph)) {
        pckt->fragment = 1;
        log_warn("ipv4 fragmented packets, %d", iph->frag_off);

        if (is_first_fragment(iph))
            pckt->fragment = 2;
    }

    return ACTION_PROCESSING;
}


int
packet_ingress(void *ptr, uint32_t len, struct packet_context *ctx, struct packet_meta *pckt)
{
    bool     is_ipv6 = false;
    bool     is_tcp = false;
    int      ret = 0;
    uint8_t  protocol = 0;
    uint16_t pkt_bytes = 0;
    uint32_t action = 0;
    char     sip[64];
    char     dip[64];

    log_info("receive packet, data:%p size:%d", ptr, len);

    /* packet context */
    if (parse_pkt_to_ctx(ptr, len, ctx) != ACTION_PROCESSING) {
        log_error("failed to parse packet to ctx, data:%p size:%d", ptr, len);
        ret = NET_EFORMAT;
        goto err;
    }
    log_info("parse packet to ctx, offset:%llu proto:0x%x", ctx->hdr_size, ctx->hdr_proto);

    /* protocol */
    switch(ctx->hdr_proto) {
    case NETP_ETHERTYPE_IP:
        action = process_headers(pckt, &protocol, &pkt_bytes, ctx);
        break;
    case NETP_ETHERTYPE_IPV6:
        log_info("ipv6 protocol, protocol:%d data:%p size:%d", ctx->hdr_proto, ptr, len);
        is_ipv6 = true;
        ret = NET_EDROP;
        break;
    case NETP_ETHERTYPE_ARP:
        log_info("arp protocol, protocol:%d data:%p size:%d", ctx->hdr_proto, ptr, len);
        ret = NET_EDROP;
        break;

    default:
        log_info("invalid protocol, protocol:%d data:%p size:%d", ctx->hdr_proto, ptr, len);
        ret = NET_EFORMAT;
        break;
    }

    if (ret != NET_OK)
        goto err;

    if (action == ACTION_DROP || action == ACTION_FORMAT) {
        log_error("failed to parse packet, ret:%d data:%p size:%d", action, ptr, len);
        ret = NET_EFORMAT;
        goto err;
    }

    /* ip protocol */
    switch(pckt->flow.proto) {
    case NETP_IPPROTO_TCP:
        if (!parse_tcp(ctx, pckt)) {
            log_error("failed to parse tcp packet, data:%p size:%d", ptr, len);
            ret = NET_EFORMAT;
        }
        is_tcp =true;
        break;
    case NETP_IPPROTO_UDP:
        if (!parse_udp(ctx, pckt)) {
            log_error("failed to parse udp packet, data:%p size:%d", ptr, len);
            ret = NET_EFORMAT;
        }
        break;
    case NETP_IPPROTO_ICMP:
        action = parse_icmp(ctx, pckt);
        if (action > 0) {
//            return action;
            log_info("imcp action: %d", action);
        }

        if (len >= MAX_PCKT_SIZE) {
            /* ICMP TOOBIG */
            log_info("icmp is too big, len:%d size:%d", len, MAX_PCKT_SIZE);
            ret = NET_EICMP;
        }
        break;
    default:
        log_error("invalid protocol, protocol:%d data:%p size:%d", ctx->hdr_proto, ptr, len);
        ret = NET_EFORMAT;
        break;
    }

    log_info("%d:%d event ==> %s:%s, %d:%d, %u:%u",
            is_ipv6, is_tcp, ip_format_string(pckt->flow.src, sip, sizeof(sip)), ip_format_string(pckt->flow.dst, dip, sizeof(dip)),
            pckt->flow.sport, pckt->flow.dport, pckt->flow.ack, pckt->flow.seq);

    log_info("payload ==> %d:%d, %d, fragment:%d",
            ctx->length, ctx->payload_len, ctx->hdr_size, pckt->fragment);

    loga_hexdump(ctx->ptr, ctx->payload_len, "payload");

err:
    if (ret != CMN_OK) {
        return ret;
    }
    return CMN_OK;
}



