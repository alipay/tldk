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

#include "ctx.h"
#include "route.h"
#include "tle_glue.h"

int v_route_add(in_addr_t dst, uint8_t dst_len, in_addr_t gw)
{
	return route_add(&default_ctx->ipv4_rt, dst, dst_len, gw);
}

int v_route_del(in_addr_t dst, uint8_t dst_len, in_addr_t gw)
{
	return route_del(&default_ctx->ipv4_rt, dst, dst_len, gw);
}
