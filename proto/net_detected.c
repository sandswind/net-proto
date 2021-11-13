#include "net.h"
#include "net_utils.h"
#include "net_detected.h"

bool is_mysql_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if(meta->flow.proto == NETP_IPPROTO_TCP) {
        if(meta->payload_size > 38  //min length
        && GET_UINT16(payload, 0) == meta->payload_size - 4   //first 3 bytes are length
        && GET_UINT8(payload, 2) == 0x00  //3rd byte of meta length
        && GET_UINT8(payload, 3) == 0x00  //meta sequence number is 0 for startup meta
        && GET_UINT8(payload, 5) > 0x30   //server version > 0
        && GET_UINT8(payload, 5) < 0x39   //server version < 9
        && GET_UINT8(payload, 6) == 0x2e  //dot
        ) {

            if(memcmp((const char*)&payload[meta->payload_size-22], "mysql_", 6) == 0) {
                log_debug("found MySQL");
                return true;
            }
        }
    }

    return false;
}

bool is_rsync_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if(meta->flow.proto == NETP_IPPROTO_TCP) {
        /*
        * Should match: memcmp(payload, "@RSYNCD: 28", 14) == 0)
        */
        if (meta->payload_size == 12 && payload[0] == 0x40 &&
        payload[1] == 0x52 && payload[2] == 0x53 &&
        payload[3] == 0x59 && payload[4] == 0x4e &&
        payload[5] == 0x43 && payload[6] == 0x44 &&
        payload[7] == 0x3a ) {
            log_debug("found rsync\n");
            return true;
        }
    }

    return false;
}

bool is_zabbix_content(struct packet_meta *meta)
{
    uint8_t tomatch[] = { 'Z', 'B', 'X', 'D', 0x1 };
    uint8_t *payload = meta->payload;

    if((meta->payload_size > 4) && (memcmp((uint8_t *)payload, tomatch, 5) == 0)) {
        log_debug("found zabbix")
        return true;
    }

    return false;    
}

bool is_smb_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    /* Check connection over TCP */
    if(meta != NULL && meta->flow.proto == NETP_IPPROTO_TCP) {

        if(meta->payload_size > (32 + 4 + 4)
        && (meta->payload_size - 4) == ntohl(GET_UINT32(payload, 0))
        ) {
            uint8_t smbv1[] = { 0xff, 0x53, 0x4d, 0x42 };
            log_debug("found SMB\n");

            if(memcmp((uint8_t *)&payload[4], smbv1, sizeof(smbv1)) == 0) {
                if(payload[8] != 0x72) /* Skip Negotiate request */ {
                    log_info("smb protocol version 1");
                    return true;
                }
            } else {
                log_info("smb protocol version 23");
            }
            return true;
        }
    }

    return false;
}


bool is_redis_content(struct packet_meta *meta)
{
    uint8_t first_char = 0;
    uint8_t *payload = meta->payload;
    uint32_t payload_len = meta->payload_size;

    if(payload_len == 0) 
        return false;

    first_char = payload[0];

    /*
    *1
    $4
    PING
    +PONG
    *3
    $3
    SET
    $19
    dns.cache.127.0.0.1
    $9
    localhost
    +OK
    */

    if (first_char != '\0') {
        if((first_char == '*')
            || (first_char == '+')
            ||  (first_char == ':')) {

            return true;
        }
    }

    return false;
}


bool is_rdp_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if (meta->payload_size > 10 && GET_UINT8(payload, 0) > 0
        && GET_UINT8(payload, 0) < 4 && GET_UINT16(payload, 2) == ntohs(meta->payload_size)
        && GET_UINT8(payload, 4) == meta->payload_size - 5
        && GET_UINT8(payload, 5) == 0xe0
        && GET_UINT16(payload, 6) == 0 && GET_UINT16(payload, 8) == 0 && GET_UINT8(payload, 10) == 0) {
            log_debug( "found RDP\n");
            return true;
    }

    return false;
}

bool is_radius_content(struct packet_meta *meta)
{
    uint32_t payload_len = meta->payload_size;
    uint8_t *payload = meta->payload;

    if(meta->flow.proto == NETP_IPPROTO_UDP) {
        struct radius_header *h = (struct radius_header*)payload;
        /* RFC2865: The minimum length is 20 and maximum length is 4096. */
        if((payload_len < 20) || (payload_len > 4096)) {
            return false;
        }

        if((h->code > 0)
        && (h->code <= 13)
        && (ntohs(h->len) == payload_len)) {
            log_debug( "Found radius\n");

            return true;
        }
    }

    return false;
}

bool is_qq_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if ((meta->payload_size == 72 && ntohl(GET_UINT32(payload, 0)) == 0x02004800) ||
        (meta->payload_size == 64 && ntohl(GET_UINT32(payload, 0)) == 0x02004000) ||
        (meta->payload_size == 60 && ntohl(GET_UINT32(payload, 0)) == 0x02004200) ||
        (meta->payload_size == 84 && ntohl(GET_UINT32(payload, 0)) == 0x02005a00) ||
        (meta->payload_size == 56 && ntohl(GET_UINT32(payload, 0)) == 0x02003800) ||
        (meta->payload_size >= 39 && ntohl(GET_UINT32(payload, 0)) == 0x28000000)) {
            log_debug( "found QQ\n");
            return true;
        }

    return false;
}

bool is_pptp_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if (meta->payload_size >= 10 && GET_UINT16(payload, 0) == htons(meta->payload_size)
        && GET_UINT16(payload, 2) == htons(0x0001)   /* message type: control message */
        &&GET_UINT32(payload, 4) == htonl(0x1a2b3c4d)    /* cookie: correct */
        &&(GET_UINT16(payload, 8) == htons(0x0001)   /* control type: start-control-connection-request */
        )) {
            log_debug( "found pptp\n");
            return true;
    }

    return false;
}

bool is_oracle_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if(meta->flow.proto == NETP_IPPROTO_TCP) {
        /* Oracle Database 9g,10g,11g */
        if ((((meta->payload_size >= 3 && payload[0] == 0x07) && (payload[1] == 0xff) && (payload[2] == 0x00))
            || ((meta->payload_size >= 232) && ((payload[0] == 0x00) || (payload[0] == 0x01))
            && (payload[1] != 0x00)
            && (payload[2] == 0x00)
            && (payload[3] == 0x00)))) {
                log_debug( "found oracle 9g, 10g, 11g\n");
                return true;
        } else if (meta->payload_size == 213 && payload[0] == 0x00 &&
                payload[1] == 0xd5 && payload[2] == 0x00 &&
                payload[3] == 0x00 ) {
                    log_debug( "found oracle\n");
                    return true;
        }
    }

    return false;
}

//bool is_ntp_content(struct packet_meta *meta)
//{
//    uint8_t *payload = payload;
//
//    if (meta->flow.proto == NETP_IPPROTO_UDP) {
//        if ((((payload[0] & 0x38) >> 3) <= 4)) {
//
//        // 38 in binary representation is 00111000
//        flow->protos.ntp.version = (payload[0] & 0x38) >> 3;
//
//        if (flow->protos.ntp.version == 2) {
//            flow->protos.ntp.request_code = payload[3];
//        }
//
//        log_debug( "found NTP\n");
//        ndpi_int_ntp_add_connection(ndpi_struct, flow);
//        return;
//        }
//    }
//
//    return false;
//}

bool is_nfs_content(struct packet_meta *meta)
{
    uint8_t offset = 0;
    uint8_t *payload = meta->payload;

    if (meta->flow.proto == NETP_IPPROTO_TCP)
        offset = 4;

    if (meta->payload_size < (40 + offset))
        goto exclude_nfs;

    if (offset != 0 && GET_UINT32(payload, 0) != htonl(0x80000000 + meta->payload_size - 4))
        goto exclude_nfs;

    if (GET_UINT32(payload, 4 + offset) != 0)
        goto exclude_nfs;

    if (GET_UINT32(payload, 8 + offset) != htonl(0x02))
        goto exclude_nfs;

    if (GET_UINT32(payload, 12 + offset) != htonl(0x000186a5)
        && GET_UINT32(payload, 12 + offset) != htonl(0x000186a3)
        && GET_UINT32(payload, 12 + offset) != htonl(0x000186a0))
        goto exclude_nfs;

    if (ntohl(GET_UINT32(payload, 16 + offset)) > 4)
        goto exclude_nfs;

    log_debug("found NFS\n");
    return true;

  exclude_nfs:
    return false;
}

bool is_tds_content(struct packet_meta *meta)
{
    struct tds_packet_header *h = (struct tds_packet_header*) meta->payload;

    if((meta->payload_size < sizeof(struct tds_packet_header))
        /*
        The TPKT protocol used by ISO 8072 (on port 102) is similar
        to this potocol and it can cause false positives
        */
        || (meta->flow.dport == ntohs(102))) {
            return false;
    }

    if((h->type >= 1 && h->type <= 8) || (h->type >= 14 && h->type <= 18)) {
        if(h->status == 0x00 || h->status == 0x01 || h->status == 0x02 || h->status == 0x04 || h->status == 0x08 || h->status == 0x09 || h->status == 0x10) {
            if(ntohs(h->length) == meta->payload_size && h->window == 0x00) {
                log_debug( "found mssql_tds\n");
                return true;
            }
        }
    }

    return false;
}


bool is_ldap_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if (meta->payload_size >= 14 && payload[0] == 0x30) {

        // simple type
        if (payload[1] == 0x0c && meta->payload_size == 14 &&
            payload[meta->payload_size - 1] == 0x00 && payload[2] == 0x02) {

            if (payload[3] == 0x01 &&
                (payload[5] == 0x60 || payload[5] == 0x61) && payload[6] == 0x07) {
                    log_debug( "found ldap simple type 1\n");
                    return true;
            }

            if (payload[3] == 0x02 &&
                (payload[6] == 0x60 || payload[6] == 0x61) && payload[7] == 0x07) {
                    log_debug( "found ldap simple type 2\n");
                    return true;
            }
        }

        // normal type
        if (payload[1] == 0x84 && meta->payload_size >= 0x84 &&
            payload[2] == 0x00 && payload[3] == 0x00 && payload[6] == 0x02) {

            if (payload[7] == 0x01 &&
                (payload[9] == 0x60 || payload[9] == 0x61 || payload[9] == 0x63 ||
                 payload[9] == 0x64) && payload[10] == 0x84) {

                    log_debug( "found ldap type 1\n");
                    return true;
            }

            if (payload[7] == 0x02 &&
                (payload[10] == 0x60 || payload[10] == 0x61 || payload[10] == 0x63 ||
                 payload[10] == 0x64) && payload[11] == 0x84) {

                    log_debug( "found ldap type 2\n");
                    return true;
            }
        }
    }

    return false;
}


bool is_bgp_content(struct packet_meta *meta)
{
    uint8_t *payload = meta->payload;

    if(meta->flow.proto == NETP_IPPROTO_TCP) {
        if(meta->payload_size > 18
        && payload[18] < 5
        && (GET_UINT64(payload, 0) == 0xffffffffffffffffULL)
        && (GET_UINT64(payload, 8) == 0xffffffffffffffffULL)
        && (ntohs(GET_UINT16(payload, 16)) <= meta->payload_size)) {

            log_debug( "found BGP\n");
            return true;
        }
    }

    return false;
}

bool is_http_request_content(struct packet_meta *meta)
{
    uint8_t *data = meta->payload;

    if(meta->flow.proto == NETP_IPPROTO_TCP) {
        switch (data[0])
        {
        case 'G':
            if (data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
                return true;
            break;

        case 'D':
            if (data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E' && data[6] == ' ')
                return true;
            break;

        case 'C':
            if (data[1] == 'O' && data[2] == 'N' && data[3] == 'N' && data[4] == 'E' && data[5] == 'C' && data[6] == 'T' && data[7] == ' ')
                return true;
            break;

        case 'T':
            if (data[1] == 'R' && data[2] == 'A' && data[3] == 'C' && data[4] == 'E' && data[5] == ' ')
                return true;
            break;

        case 'H':
            if (data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ')
                return true;
            break;

        case 'O':
            if (data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && data[4] == 'O' && data[5] == 'N' && data[6] == 'S' && data[7] == ' ')
                return true;
            break;

        case 'P':
            switch (data[1])
            {
            case 'U':
                if (data[2] == 'T' && data[3] == ' ')
                    return true;
                break;

            case 'O':
                if (data[2] == 'S' && data[3] == 'T' && data[4] == ' ')
                    return true;
                break;

            case 'A':
                if (data[2] == 'T' && data[3] == 'C' && data[4] == 'H' && data[5] == ' ')
                    return true;
                break;
            }
            break;
        }

    }

    return false;
}
