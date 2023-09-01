/*
 * Copyright (c) 2024 Ant Group Corporation.
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

#ifndef _GVISOR_GLUE_H_
#define _GVISOR_GLUE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/epoll.h>

// stack initialization operations
int plugin_preinitstack(int pid, char **init_str_ptr, int **fds, int *num);
int plugin_initstack(const char *net_config, int *fds, int num);

// socket event-related operations
int plugin_epoll_create(void);
int plugin_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int plugin_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

// socket control-path operations
int plugin_socket(int domain, int type, int protocol, uint64_t *err);
int plugin_listen(int sockfd, int backlog, uint64_t *err);
int plugin_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint64_t *err);
int plugin_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err);
int plugin_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint64_t *err);
int plugin_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen, uint64_t *err);
int plugin_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen, uint64_t *err);
int plugin_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err);
int plugin_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err);
int plugin_ioctl(int fd, uint64_t *err, unsigned long int request, void *buf);
int plugin_shutdown(int sockfd, int how, uint64_t *err);
int plugin_close(int fd);
int plugin_readiness(int fd, int events);

// socket data-path (ingress) operations
ssize_t plugin_recv(int sockfd, void *buf, size_t len, int flags, uint64_t *err);
ssize_t plugin_recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen, uint64_t *err);
ssize_t plugin_recvmsg(int sockfd, struct msghdr *msg, int flags, uint64_t *err);
ssize_t plugin_read(int fd, void *buf, size_t count, uint64_t *err);
ssize_t plugin_readv(int fd, const struct iovec *iov, int iovcnt, uint64_t *err);

// socket data-path (egress) operations
ssize_t plugin_send(int sockfd, const void *buf, size_t len, int flags, uint64_t *err);
ssize_t plugin_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen, uint64_t *err);
ssize_t plugin_sendmsg(int sockfd, const struct msghdr *msg, int flags, uint64_t *err);
ssize_t plugin_write(int fd, const void *buf, size_t count, uint64_t *err);
ssize_t plugin_writev(int fd, const struct iovec *iov, int iovcnt, uint64_t *err);

#endif
