#ifndef LINK_H_
#define LINK_H_

#include "gaze.h"
#include "hash.h"

struct link_value_t;

#define GAZE_MAX_LINK_NUM 19997

int link_create();
struct link_value_t* link_find(link_key_t*);
struct link_value_t* link_insert(link_key_t*);
struct link_value_t* link_find_insert(link_key_t*, int is_send);
void link_erase(link_key_t*);
void link_release();

void link_key_init(link_key_t* key, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

void link_value_on_seq(struct link_value_t*, uint32_t seq);
void link_value_on_ack(link_key_t*, struct link_value_t*, uint32_t ack);
void link_value_on_psh(struct link_value_t*, uint32_t seq, int bytes, const char*);
void link_value_on_fin(struct link_value_t*, uint32_t seq);

int link_value_is_finish(struct link_value_t*);

#endif

