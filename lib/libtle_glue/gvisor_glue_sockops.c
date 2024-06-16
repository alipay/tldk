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

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>

#include "gvisor_glue.h"
#include "tle_glue.h"

/*
 * The following functions implement socket event-related operations.
 */

int plugin_epoll_create(void)
{
    return PRE(epoll_create)(1);
}

int plugin_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return PRE(epoll_ctl)(epfd, op, fd, event);
}

int plugin_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    int ret;
    ret = PRE(epoll_wait)(epfd, events, maxevents, timeout);
    return ret;
}

/*
 * The following functions implement socket control-path operations.
 */

int plugin_socket(int domain, int type, int protocol, uint64_t *err)
{
	int ret;
    ret = PRE(socket)(domain, type, protocol);
    *err = errno;
    return ret;
}

int plugin_listen(int sockfd, int backlog, uint64_t *err)
{
    int ret;
    ret = PRE(listen)(sockfd, backlog);
    *err = errno;
    return ret;
}

int plugin_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(bind)(sockfd, addr, addrlen);
    *err = errno;
    return ret;
}

int plugin_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(accept)(sockfd, addr, addrlen);
    *err = errno;
    return ret;
}

int plugin_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(connect)(sockfd, addr, addrlen);
    *err = errno;
    return ret;
}

int plugin_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen, uint64_t *err)
{
    int ret;
    ret = PRE(getsockopt)(sockfd, level, optname, optval, optlen);
    *err = errno;
    return ret;               
}

int plugin_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen, uint64_t *err)
{
    int ret;
    ret = PRE(setsockopt)(sockfd, level, optname, optval, optlen);
    *err = errno;
    return ret;
}

int plugin_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(getsockname)(sockfd, addr, addrlen);
    *err = errno;
    return ret;
}

int plugin_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(getpeername)(sockfd, addr, addrlen);
    *err = errno;
    return ret;
}

int plugin_ioctl(int fd, uint64_t *err, unsigned long int request, void *buf)
{
    int ret;
    ret = PRE(ioctl)(fd, request, buf);
    *err = errno;
    return ret;
}

int plugin_shutdown(int sockfd, int how, uint64_t *err)
{
    int ret;
    ret = PRE(shutdown)(sockfd, how);
    *err = errno;
    return ret;
}

int plugin_close(int fd)
{
    int ret;
    ret = PRE(close)(fd);
    return ret;
}

int plugin_readiness(int fd, int events) {
    int ret;
    ret = fd_ready(fd, events);
    return ret;
}

/*
 * The following functions implement socket data-path (ingress) operations.
 */

ssize_t plugin_recv(int sockfd, void *buf, size_t len, int flags, uint64_t *err)
{
    int ret;
    ret = PRE(recv)(sockfd, buf, len, flags);
    *err = errno;
    return ret;
}

ssize_t plugin_recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
    *err = errno;
    return ret;
}

ssize_t plugin_recvmsg(int sockfd, struct msghdr *msg, int flags, uint64_t *err)
{
    int ret;
    ret = PRE(recvmsg)(sockfd, msg, flags);
    *err = errno;
    return ret;
}

ssize_t plugin_read(int fd, void *buf, size_t count, uint64_t *err)
{
    int ret;
    ret = PRE(read)(fd, buf, count);
    *err = errno;
    return ret;
}

ssize_t plugin_readv(int fd, const struct iovec *iov, int iovcnt, uint64_t *err)
{
    int ret;
    ret = PRE(readv)(fd, iov, iovcnt);
    *err = errno;
    return ret;
}

/*
 * The following functions implement socket data-path (egress) operations.
 */

ssize_t plugin_send(int sockfd, const void *buf, size_t len, int flags, uint64_t *err)
{
    int ret;
    ret = PRE(send)(sockfd, buf, len, flags);
    *err = errno;
    return ret;
}

ssize_t plugin_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen, uint64_t *err)
{
    int ret;
    ret = PRE(sendto)(sockfd, buf, len, flags, dest_addr, addrlen);
    *err = errno;
    return ret;
}

ssize_t plugin_sendmsg(int sockfd, const struct msghdr *msg, int flags, uint64_t *err)
{
    int ret;
    ret = PRE(sendmsg)(sockfd, msg, flags);
    *err = errno;
    return ret;
}

ssize_t plugin_write(int fd, const void *buf, size_t count, uint64_t *err)
{
   int ret;
    ret = PRE(write)(fd, buf, count);
    *err = errno;
    return ret;
}

ssize_t plugin_writev(int fd, const struct iovec *iov, int iovcnt, uint64_t *err)
{
    int ret;
    ret = PRE(writev)(fd, iov, iovcnt);
    *err = errno;
    return ret;
}
