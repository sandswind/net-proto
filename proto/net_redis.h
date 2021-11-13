#ifndef __NET_REDIS_H
#define __NET_REDIS_H

#include "cmn.h"


int format_redis(char *payload, int size, char *out, int out_size);

int format_memcached(char *payload, int size, char *out, int out_size);

#endif
