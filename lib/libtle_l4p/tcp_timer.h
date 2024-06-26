/*
 * Copyright (c) 2016  Intel Corporation.
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

#ifndef _TCP_TIMER_H_
#define _TCP_TIMER_H_

#include <tle_timer.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * internal defines.
 * all RTO values are in ms.
 */
#define	TCP_RTO_MAX	60000U        /* RFC 6298 (2.5) */
#define	TCP_RTO_MIN	200U          /* Linux/include/net/tcp.h: TCP_RTO_MIN */
#define	TCP_RTO_2MSL	(2 * TCP_RTO_MAX)
#define	TCP_RTO_DEFAULT	1000U   /* RFC 6298 (2.1)*/
#define	TCP_RTO_GRANULARITY	100U

static inline struct tle_tcp_stream *
timer_stream(struct tle_tcp_stream *s)
{
	return (struct tle_tcp_stream *)((unsigned long)s & (~(unsigned long)TIMER_MASK));
}

static inline uint8_t
timer_type(struct tle_tcp_stream *s)
{
	return (uint8_t)((unsigned long)s & (unsigned long)TIMER_MASK);
}

static inline void
timer_stop(struct tle_tcp_stream *s, uint8_t type)
{
	struct tle_timer_wheel *tw;

	if (s->timer.handle[type] != NULL) {
		tw = CTX_TCP_TMWHL(s->s.ctx);
		tle_timer_stop(tw, s->timer.handle[type]);
		s->timer.handle[type] = NULL;
	}
}

static inline void
timer_start(struct tle_tcp_stream *s, uint8_t type, uint32_t timeout)
{
	struct tle_timer_wheel *tw;

	if (s->timer.handle[type] == NULL) {
		tw = CTX_TCP_TMWHL(s->s.ctx);
		s->timer.handle[type] = tle_timer_start(tw, (void*)((unsigned long)s | type), timeout);
	}
}

static inline void
timer_restart(struct tle_tcp_stream *s, uint8_t type, uint32_t timeout)
{
	struct tle_timer_wheel *tw;

	tw = CTX_TCP_TMWHL(s->s.ctx);
	s->timer.handle[type] = tle_timer_start(tw, (void*)((unsigned long)s | type), timeout);
}


/*
 * reset number of retransmissions and restart RTO timer.
 */
static inline void
timer_reset(struct tle_tcp_stream *s, uint8_t type, uint32_t timeout)
{
	timer_stop(s, type);
	timer_start(s, type, timeout);
}

static inline uint32_t
rto_roundup(uint32_t rto)
{
	rto = RTE_MAX(rto, TCP_RTO_MIN);
	rto = RTE_MIN(rto, TCP_RTO_MAX);
	return rto;
}

/*
 * RFC6298: Computing TCP's Retransmission Timer
 * RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
 * SRTT <- (1 - alpha) * SRTT + alpha * R'
 * RTO <- SRTT + max (G, K*RTTVAR)
 * the following computation is based on Jacobson'88 paper referenced
 * in the RFC6298
*/
static inline void
rto_estimate(struct tcb *tcb, int32_t rtt)
{
	uint32_t rto;

	if (!rtt)
		rtt = 1;
	if (tcb->rcv.srtt) {
		rtt -= (tcb->rcv.srtt >> 3); /* alpha = 1/8 */
		tcb->rcv.srtt += rtt;

		if (rtt < 0)
			rtt = -rtt;
		rtt -= (tcb->rcv.rttvar >> 2); /* beta = 1/4 */
		tcb->rcv.rttvar += rtt;

	} else {
		tcb->rcv.srtt = rtt << 3;
		tcb->rcv.rttvar = rtt << 1;
	}

	rto = (tcb->rcv.srtt >> 3) +
		RTE_MAX(TCP_RTO_GRANULARITY, tcb->rcv.rttvar);
	tcb->snd.rto = rto_roundup(rto);
}

#ifdef __cplusplus
}
#endif

#endif /* _TCP_TIMER_H_ */
