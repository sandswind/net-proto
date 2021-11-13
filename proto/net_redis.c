#include "net.h"
#include "net_utils.h"


int format_memcached(char *payload, int size, char *out, int out_size)
{
    int n = 0;
    int copy_size = 0;
    int buf_size = 0;
    char *pos = NULL;
    char *buf = out;
    char *start = NULL;

    buf_size = size > out_size ? out_size : size;
    start = payload;

    pos = strstr(start, "\r\n");
    while (pos != NULL) {
        copy_size = pos-start < buf_size-n ? pos-start : buf_size-n;
        memcpy(buf+n, start, copy_size);
        n += copy_size;
        if (n >= buf_size)
            break;
        buf[++n] = ' ';
        if (pos-payload+2 >= size)
            break;

        start = pos+2;
        pos = strstr(start, "\r\n");
    }

    if (n == 0) {
        memcpy(buf, payload, buf_size);
        buf[buf_size-1] = '\0';
//        n = buf_size;
    } else {
        buf[n-1] = '\0';
    }

    return n;
}


int format_redis(char *payload, int size, char *out, int out_size)
{
    int n = 0;
    int copy_size = 0;
    int buf_size = 0;
    int fields = 0;
    char *start = NULL;
    char *pos = NULL;
    char *buf = out;

    if (payload[0] != '*') {
        return format_memcached(payload, size, out, out_size);
    }

    buf_size = size > out_size ? out_size : size;
    start = payload;

    pos = strstr(start, "\r\n");
    while(pos != NULL) {
        if (fields != 0 && fields % 2 == 0) {
            copy_size = pos-start < buf_size - n ? pos-start : buf_size-n;
            memcpy(buf+n, start, copy_size);
            n += copy_size;
            if (n >= buf_size)
                break;
            buf[n++] = ' ';
        }

        if (pos-payload+2 >= size)
            break;
        start = pos+2;
        fields++;

        pos = strstr(start, "\r\n");
    }

    if (n == 0) {
        memcpy(buf, payload, buf_size);
        buf[buf_size-1] = '\0';
//        n = buf_size;
    } else {
        buf[n-1] = '\0';
    }

    return n;;
}
