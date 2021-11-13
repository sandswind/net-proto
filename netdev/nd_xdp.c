#include "nd_xdp.h"

int
get_ifindex(const char *raw_ifname)
{
    int if_index = 0;
    char ifname_buf[MAX_IFNAME_LEN] = {0};
    char *ifname = NULL;

    if (strlen(raw_ifname) >= MAX_IFNAME_LEN) {
        log_error("device name '%s' too long: must be less than %d characters", raw_ifname, MAX_IFNAME_LEN);
        return CMN_EXDP;
    }

    ifname = (char *)&ifname_buf;
    strncpy(ifname, raw_ifname, MAX_IFNAME_LEN);

    if_index = if_nametoindex(ifname);
    if (if_index == 0) {
        log_error("device name '%s' not found err(%d): %s", raw_ifname, errno, strerror(errno));
        return CMN_EXDP;
    }

    return if_index;
}

static int
load_section(struct bpf_object *bpf_obj, char *section)
{
    struct bpf_program *bpf_prog = NULL;

    bpf_prog = bpf_object__find_program_by_title(bpf_obj, section);
    if (bpf_prog == NULL) {
        log_error("unable to find program, section:%s, error:%s", section, strerror(errno));
        return CMN_ERROR;
    }

    return bpf_program__fd(bpf_prog);
}

int
attach(int if_index, char *prog_path, char *section, uint32_t xdp_flags)
{
    struct bpf_object *bpf_obj = NULL;
    int bpf_prog_fd = -1;
    int ret = CMN_ERROR;

    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0) {
        log_error("unable to load XDP program, path:%s, error:%s", prog_path, strerror(-ret));
        return CMN_EXDP;
    }

    int section_fd = load_section(bpf_obj, section);
    if (section_fd < 0) {
        log_warn("unable to load section '%s' from load bpf object file '%s', error:%s",
               section, prog_path, strerror(-section_fd));
    } else {
        bpf_prog_fd = section_fd;
    }

    ret = bpf_set_link_xdp_fd(if_index, bpf_prog_fd, xdp_flags);
    if (ret != 0) {
        log_error("unable to attach loaded XDP program to specified device, index:%d, error:%s", if_index, strerror(-ret));
        return CMN_EXDP;
    }

    ret = bpf_object__pin_maps(bpf_obj, MAP_DIR);
    if (ret != 0) {
        log_error("unable to pin the loaded and attached XDP program's maps to '%s', error:%s",
               MAP_DIR, strerror(-ret));
        return CMN_EPIN;
    }

    return CMN_OK;
}

int
detach(int if_index, char *prog_path, uint32_t xdp_flags)
{
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = CMN_ERROR;

    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0) {
        log_error("unable to load XDP program from file '%s', error: %s", prog_path, strerror(-ret));
        return CMN_EXDP;
    }

    ret = bpf_set_link_xdp_fd(if_index, -1, xdp_flags);
    if (ret != 0) {
        log_error("can not detach XDP program from specified device at index '%d', error:%s",
               if_index, strerror(-ret));
    }

    ret = bpf_object__unpin_maps(bpf_obj, MAP_DIR);
    if (ret != 0) {
        log_error("unable to unpin the XDP program's '%s' maps from '%s', error: %s",
                prog_path, MAP_DIR, strerror(-ret));
    }

    return CMN_OK;
}

int
open_bpf_map(const char *file)
{
    int fd = -1;

    fd = bpf_obj_get(file);
    if (fd < 0) {
        log_error("failed to open bpf map file: '%s', error: %s", file, strerror(errno));
        return CMN_EMAP;
    }
    return fd;
}

int
update_map(const char *map, void *key, bool is_insert)
{
    if (is_insert) {
        uint8_t value = 0;

        return update_map_key(map, key, &value);
    }

    return delete_map_key(map, key);
}

int
update_map_key(const char *map, void *key, void *value)
{
    int map_fd = open_bpf_map(map);
    if (map_fd < 0) {
        return CMN_ERROR;
    }

    if (bpf_map_update_elem(map_fd, key, value, BPF_NOEXIST) != 0) {
        log_error("failed to update map, key:%02X, value:%02X", key, value);
        return CMN_EMAP;
    }

    return CMN_OK;
}

int
delete_map_key(const char *map, void *key)
{
    int map_fd = open_bpf_map(map);
    if (map_fd < 0) {
        return CMN_ERROR;
    }

    if (bpf_map_delete_elem(map_fd, key) != 0) {
        log_error("failed to delete map by key %02X", key);
        return CMN_EMAP;
    }

    return CMN_OK;
}
