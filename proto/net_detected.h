#ifndef __NET_DETECTED_H
#define __NET_DETECTED_H

#include "net.h"

#define MATCH_PORT_ONE(a, b, c)  (((a == c) || (b == c)) ? 1 : 0)

#pragma pack(push, 1)
struct radius_header {
    uint8_t code;
    uint8_t packet_id;
    uint16_t len;
};


struct tds_packet_header {
    uint8_t type;
    uint8_t status;
    uint16_t length;
    uint16_t channel;
    uint8_t number;
    uint8_t window;
};

#pragma pack(pop)

static inline bool check_mysql_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 3306);
}

static inline bool check_oracle_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 1521);
}

static inline bool check_redis_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 6379);
}

static inline bool check_http_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 80);
}

static inline bool check_https_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 443);
}

static inline bool check_smb_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 445);
}

static inline bool check_bgp_port(uint16_t proto, uint16_t sport, uint16_t dport)
{
    if (proto != NETP_IPPROTO_TCP)
        return false;

    return MATCH_PORT_ONE(sport, dport, 179);
}


bool is_mysql_content(struct packet_meta *meta);
bool is_rsync_content(struct packet_meta *meta);
bool is_zabbix_content(struct packet_meta *meta);
bool is_smb_content(struct packet_meta *meta);
bool is_redis_content(struct packet_meta *meta);
bool is_rdp_content(struct packet_meta *meta);
bool is_radius_content(struct packet_meta *meta);
bool is_qq_content(struct packet_meta *meta);
bool is_pptp_content(struct packet_meta *meta);
bool is_oracle_content(struct packet_meta *meta);
bool is_ntp_content(struct packet_meta *meta);
bool is_nfs_content(struct packet_meta *meta);
bool is_tds_content(struct packet_meta *meta);
bool is_ldap_content(struct packet_meta *meta);
bool is_bgp_content(struct packet_meta *meta);
bool is_http_request_content(struct packet_meta *meta);

#endif
