#ifndef __NET_UTILS_H
#define __NET_UTILS_H

#include "cmn.h"

struct pkg_text_item {
    int32_t      len;
    int32_t      type;
    char     *item;
};

struct pkg_kv_item {
    int32_t      key_len;
    int32_t      value_len;
    char     *key;
    char     *value;
};

struct pkg_tlv_item
{
    uint8_t type;
    uint8_t len;
    uint8_t *value;
};

static inline int8_t get_tlv_value_int8(struct pkg_tlv_item *item, int32_t offset)
{
    if (item == NULL || item->len - offset < 1)
        return (-1);

    return item->value[0];
}


static inline int16_t get_tlv_value_int16(struct pkg_tlv_item *item, int32_t offset)
{
    uint16_t value = 0;

    if (item == NULL || item->len - offset < 1)
        return (-1);

    memcpy((char *)&value, (char *)item->value, sizeof(int16_t));
    return htobe16(value);
}


static inline int32_t get_tlv_value_int32(struct pkg_tlv_item *item, int32_t offset)
{
    uint32_t value = 0;
    if (item == NULL || item->len - offset < 1)
        return (-1);

    memcpy((char *)&value, (char *)item->value, sizeof(uint32_t));
    return htobe32(value);
}

static inline char *get_tlv_value_string(struct pkg_tlv_item *item, int32_t offset)
{
    if (item == NULL || item->len - offset < 1)
        return NULL;

    return (char*)item->value + offset;
}

static inline int32_t get_tlv_total_size(struct pkg_tlv_item *item)
{
    if (item == NULL)
        return sizeof(uint8_t);

    return sizeof(uint8_t) * 2 + (int32_t)item->len;
}

static inline int32_t get_tlv_data_Size(struct pkg_tlv_item *item)
{
    if (item == NULL)
        return 0;

    return item->len;
}

char *mac_format_string(uint8_t *mac_address, char *out, int32_t out_size);
int32_t ip_format_int(char *address);
char *ip_format_string(int32_t ip_address, char *out, int32_t out_size);

int32_t pkg_kv_split(char *line, char delim, bool is_cut, struct pkg_kv_item *item);
int32_t pkg_text_split(char *line, char delim, struct pkg_text_item *items);


struct pkg_tlv_item *get_tlv_first_record(uint8_t* data, int32_t data_size);
struct pkg_tlv_item *get_tlv_next_record(uint8_t* data, int32_t data_size, int32_t offset);
struct pkg_tlv_item *get_tlv_record(uint8_t type, uint8_t* data, int32_t data_size);
int32_t get_tlv_record_count(uint8_t* data, int32_t data_size);

#endif
