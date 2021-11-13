#include "cmn_base.h"
#include "cmn_log.h"

#include "net_utils.h"

char *
mac_format_string(uint8_t *mac_address, char *out, int32_t out_size)
{
    if (out_size == 0)
        return NULL;

    snprintf(out, out_size, "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)mac_address[0],
        (unsigned char)mac_address[1],
        (unsigned char)mac_address[2],
        (unsigned char)mac_address[3],
        (unsigned char)mac_address[4],
        (unsigned char)mac_address[5]);

    return out;
}

int32_t
ip_format_int(char *address)
{
    int32_t ret = 0;
    struct in_addr ip;

    if (address == NULL)
        return CMN_PARAMETER;

    ret = inet_pton(AF_INET, address, &ip);
    if(ret <= 0){
        log_error("inet_pton:ip,%s errno:%d", address, errno);
        return 0;
    }

    return ip.s_addr;
}

char *
ip_format_string(int32_t ip_address, char *out, int32_t out_size)
{
    struct in_addr ip;
    char addr[16] = {0};
    char *str = NULL;

    if (out_size == 0)
        return NULL;

    ip.s_addr = ip_address;
    str = (char*)inet_ntop(AF_INET, &ip, addr, sizeof(addr));
    if(str == NULL){
        log_error("inet_ntop:ip, 0x%x, errno:%d", ip.s_addr, errno);
        return NULL;
    }

    snprintf(out, out_size, "%s", str);
    return out;
}

int32_t
pkg_kv_split(char *line, char delim, bool is_cut, struct pkg_kv_item *item)
{
    int32_t  count = 0;
    int32_t  i = 0;
    int32_t  len = strlen(line);
    char *pos = line;
    char *offset = line;
    char *tail = line + len;

    if (line == NULL) {
        return count;
    }

    while(*pos != '\0' && pos <= tail) {
        if (*pos == delim) {
            item->key = offset;
            item->key_len = pos - offset;

            pos++;

            item->value = pos;
            item->value_len = tail - pos;
        }
        pos++;
    }

    if (item->key_len == 0 && item->value_len == 0) {
        return CMN_ERROR;
    }

    if (is_cut) {
        if (item->key_len > 0) {
            pos = item->key;
            len = item->key_len;

            for (i = 0; i < len; i++) {
                if (*pos == ' ' || *pos == '\t') {
                    pos++;
                    item->key++;
                    item->key_len--;
                }else {
                    break;
                }
            }

            tail = pos + item->key_len;
            len = item->key_len;
            for (i = len; i > 0; i--) {
                if (*tail == ' ' || *tail == '\t' || *tail == '\r') {
                    tail--;
                    item->key_len--;
                }else {
                    break;
                }
            }
        }

        if (item->value_len > 0) {
            pos = item->value;
            len = item->value_len;

            for (i = 0; i < len; i++) {
                if (*pos == ' ' || *pos == '\t') {
                    pos++;
                    item->value++;
                    item->value_len--;
                }else {
                    break;
                }
            }

            tail = pos + item->value_len;
            len = item->value_len;
            for (i = len; i > 0; i--) {
                if (*tail == ' ' || *tail == '\t' || *tail == '\r') {
                    tail--;
                    item->value_len--;
                }else {
                    break;
                }
            }
        }
    }

    return CMN_OK;
}

int32_t
pkg_text_split(char *line, char delim, struct pkg_text_item *items)
{
    int32_t  count = 0;
    int32_t  i = 0;
    int32_t  len = strlen(line);
    char *pos = line;
    char *offset = line;
    char *tail = line + len;

    if (line == NULL) {
        return count;
    }

    if (delim != ' ' && delim != '\t') {
        for (i = len; i > 0; i--) {
            if (*tail == ' ' || *tail == '\t' || *tail == '\r') {
                tail--;
                len--;
            }else {
                break;
            }
        }
    }

    if (delim != ' ' && delim != '\t') {
        for (i = 0; i < len; i++) {
            if (*pos == ' ' || *pos == '\t') {
                pos++;
                offset++;
            }else {
                break;
            }
        }
    }

    while(*pos != '\0' && pos <= tail) {
        if (*pos == delim) {
            items[count].item = offset;
            items[count].len = pos - offset;
            count++;
            offset = pos;
            offset++;
        }
        pos++;
    }

    return count;
}


struct pkg_tlv_item *
get_tlv_first_record(uint8_t* data, int32_t data_size)
{
    if (data == NULL || data_size < sizeof(struct pkg_tlv_item))
       return NULL;

    return (struct pkg_tlv_item *)data;
}


struct pkg_tlv_item *
get_tlv_next_record(uint8_t* data, int32_t data_size, int32_t offset)
{
    struct pkg_tlv_item *item = NULL;

    if (data == NULL || data_size <= 0)
        return NULL;

    // record pointer is out-bounds of the TLV records memory
    if (data_size - offset < sizeof(struct pkg_tlv_item))
        return NULL;


    item = (struct pkg_tlv_item *)data + offset;
    if (get_tlv_total_size(item) == 0)
        return NULL;

    return item;
}


struct pkg_tlv_item *
get_tlv_record(uint8_t type, uint8_t* data, int32_t data_size)
{
    int32_t offset = 0;
    struct pkg_tlv_item *item = get_tlv_first_record(data, data_size);


    while (item != NULL)
    {
        if (item->type == type)
            return item;
        offset += get_tlv_total_size(item);
        item = get_tlv_next_record(data, data_size, offset);
    }

    if (item == NULL) {
        log_warn("no found tlv data by type, %d", type);
    }

    return item;
}


int32_t
get_tlv_record_count(uint8_t* data, int32_t data_size)
{
    int32_t offset = 0;
    int32_t count  = 0;
    struct pkg_tlv_item *item = get_tlv_first_record(data, data_size);

    while (item != NULL)
    {
        count ++;

        offset += get_tlv_total_size(item);
        item = get_tlv_next_record(data, data_size, offset);
    }

    return count;
}

