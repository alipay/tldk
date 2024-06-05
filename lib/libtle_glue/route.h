/*
 * Copyright (c) 2020 Ant Financial Services Group.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _TLE_ROUTE_H_
#define _TLE_ROUTE_H_

#include <stdint.h>
#include <netinet/in.h>
#include <sys/queue.h>

#include <rte_rwlock.h>
#include <rte_mempool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ROUTE_NUM 1024
#define ROUTE_NO_GATEWAY ((uint32_t)(-1))

struct route_entry {
	STAILQ_ENTRY(route_entry) link;
	in_addr_t dst;
	in_addr_t mask;
	in_addr_t gw;
};

struct route_table {
	uint16_t cnt;
	rte_rwlock_t lock;
	STAILQ_HEAD(, route_entry) head;
	struct rte_mempool *pool;
};

static inline in_addr_t
convert_mask(uint8_t mask_len)
{
	return htonl(0xffffffffUL << (32 - mask_len));
}

static inline int
route_add(struct route_table *table, in_addr_t dst,
	  uint8_t dst_len, in_addr_t gw)
{
	struct route_entry *entry, *pre;
	in_addr_t mask;

	rte_rwlock_write_lock(&table->lock);
	pre = NULL;
	mask = convert_mask(dst_len);
	STAILQ_FOREACH(entry, &table->head, link) {
		if (entry->mask == mask && entry->dst == dst) {
			rte_rwlock_write_unlock(&table->lock);
			return -EEXIST;
		}
		if (ntohl(entry->mask) < ntohl(mask))
			break;
		pre = entry;
	}
	if (rte_mempool_get(table->pool, (void**)&entry) != 0) {
		rte_rwlock_write_unlock(&table->lock);
		return -ENFILE;
	}
	entry->dst = dst;
	entry->mask = mask;
	entry->gw = gw;
	if (pre == NULL)
		STAILQ_INSERT_HEAD(&table->head, entry, link);
	else
		STAILQ_INSERT_AFTER(&table->head, pre, entry, link);
	table->cnt++;
	rte_rwlock_write_unlock(&table->lock);
	return 0;
}

static inline int
route_del(struct route_table *table, in_addr_t dst,
	  uint8_t dst_len, in_addr_t gw)
{
	struct route_entry *entry;
	in_addr_t mask;

	rte_rwlock_write_lock(&table->lock);
	table->cnt--;
	mask = convert_mask(dst_len);
	STAILQ_FOREACH(entry, &table->head, link) {
		if (ntohl(entry->mask) < ntohl(mask)) {
			entry = NULL;
			break;
		}
		if (entry->dst == dst && entry->mask == mask &&
		    (gw == 0 || entry->gw == gw))
			break;
	}
	if (entry == NULL) {
		rte_rwlock_write_unlock(&table->lock);
		return -ESRCH;
	}
	STAILQ_REMOVE(&table->head, entry, route_entry, link);

	rte_mempool_put(table->pool, entry);
	rte_rwlock_write_unlock(&table->lock);
	return 0;
}

/* route_lookup searches route table to find gateway for dst address.
 * Return ROUTE_NO_GATEWAY(-1) if no gateway is found in route table for dst.
 * Otherwise return gateway for dst. Gateway is 0 means dst address is
 * in the same subnet and gateway is not needed.
 */
static inline in_addr_t
route_lookup(struct route_table *table, in_addr_t dst)
{
	struct route_entry *entry;
	in_addr_t gw = ROUTE_NO_GATEWAY;

	if (table->cnt == 0)
		return 0;

	rte_rwlock_read_lock(&table->lock);
	STAILQ_FOREACH(entry, &table->head, link) {
		if ((dst & entry->mask) == entry->dst) {
			gw = entry->gw;
			break;
		}
	}
	rte_rwlock_read_unlock(&table->lock);
	return gw;
}

static inline void
route_table_init(struct route_table *table, uint32_t socket_id,
		 in_addr_t local_addr, uint8_t local_ml, in_addr_t def_gw)
{
	in_addr_t local_mask;

	table->cnt = 0;
	rte_rwlock_init(&table->lock);
	STAILQ_INIT(&table->head);
	table->pool = rte_mempool_create("route_pool", MAX_ROUTE_NUM,
					 sizeof(struct route_entry), 0, 0, NULL,
					 NULL, NULL, NULL, socket_id, 0);
	if (table->pool == NULL)
		rte_panic("Failed to init route table");

	local_mask = convert_mask(local_ml);
	route_add(table, local_addr&local_mask, local_ml, 0);
	route_add(table, 0, 0, def_gw);
}

#ifdef __cplusplus
}
#endif

#endif /* _TLE_ROUTE_H_ */
