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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "gvisor_glue.h"
#include "tle_glue.h"
#include "util.h" 
#include "init.h"
#include "internal.h"

#define INIT_STR_LEN 120
#define INIT_FD_NUM 2

#define NS_PATH_BUF_SIZE 80

#define MACADDR_BUF_SIZE 20
#define MACADDR_LEN 17
#define GW_BUF_SIZE 1024

#define ARGV_BUF_SIZE 16
#define VDEV_BUF_SIZE 120
#define DRVARGS_BUF_SIZE 100
#define PREFIX_BUF_SIZE 11
#define FILE_PREFIX_SIZE 30
#define INITARG_KEY_SIZE 20
#define INITARG_VALUE_SIZE 20

static int
get_gatewayip(char *gatewayip, socklen_t size)
{
	char buffer[256];  // Line buffer
    char iface[16];    // Interface name
    char dest[9];      // Destination address
    char gateway[9];   // Gateway address (this is what we're looking for)
    int found_default = 0;
	unsigned char gw[4];

    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) {
        perror("Error opening /proc/net/route");
        return -1;
    }

    // Skip the first line, which is the header
    if (fgets(buffer, sizeof(buffer), route_fd) != NULL) {
        // Read each line and look for the default route
        while (fgets(buffer, sizeof(buffer), route_fd) != NULL) {
            // The file is tab-delimited with the following columns:
            // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
            // Example line:
            // eth0  00000000  0102A8C0  0003  0  0  100  00000000  0  0  0
            sscanf(buffer, "%15s %8s %8s", iface, dest, gateway);
            // Check if the destination is the default route (0.0.0.0)
            if (strcmp(dest, "00000000") == 0) {
                found_default = 1;
                break;
            }
        }
    }
    fclose(route_fd);

    if (!found_default) {
        fprintf(stderr, "Default route not found\n");
        return -1;
    }

    // Convert the gateway address from hex to dot-decimal notation
    sscanf(gateway, "%2hhx%2hhx%2hhx%2hhx", &gw[3], &gw[2], &gw[1], &gw[0]);
    snprintf(gatewayip, size, "%d.%d.%d.%d", gw[0], gw[1], gw[2], gw[3]);
    return 0;
}

static const char*
get_ns_name(int ns_type)
{
	switch (ns_type) {
	case CLONE_NEWCGROUP:
		return "cgroup";
	case CLONE_NEWIPC:
		return "ipc";
	case CLONE_NEWNS:
		return "mnt";
	case CLONE_NEWNET:
		return "net";
	case CLONE_NEWPID:
		return "pid";
	case CLONE_NEWUSER:
		return "user";
	case CLONE_NEWUTS:
		return "uts";
	default:
		rte_panic("unknown ns_type: %d\n", ns_type);
	}
}

static int
apply_ns(int target_pid, int ns_type)
{
	char old_ns_path[NS_PATH_BUF_SIZE], new_ns_path[NS_PATH_BUF_SIZE];
	int old_ns_fd, new_ns_fd;
	
	sprintf(old_ns_path, "/proc/self/ns/%s", get_ns_name(ns_type));
	old_ns_fd = open(old_ns_path, O_RDONLY | O_CLOEXEC);
	if (old_ns_fd == -1)
		return -1;
	sprintf(new_ns_path, "/proc/%d/ns/%s", target_pid, get_ns_name(ns_type));
	new_ns_fd = open(new_ns_path, O_RDONLY | O_CLOEXEC);
	if (new_ns_fd == -1) {
		close(old_ns_fd);
		return -1;
	}
	if (setns(new_ns_fd, ns_type) == -1) {
		close(old_ns_fd);
		close(new_ns_fd);
		return -1;
	}
	return old_ns_fd;
}

static int
restore_ns(int nsfd, int ns_type)
{
	if (setns(nsfd, ns_type) == -1) {
		close(nsfd);
		return -1;
	}
	return 0;
}

static int
getPrefix(uint32_t sin_addr)
{
    int ret = 0;
    uint32_t a = sin_addr;
    while (a) {
        ret++;
        a >>= 1;
    }
    return ret;
}

static int
remove_address(struct ifaddrs *ifa)
{
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket for remove address");
		return -1;
	}

    strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ);

    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    addr->sin_addr.s_addr = inet_addr("0.0.0.0");

    ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
    close(sockfd);

    if (ret < 0) {
        perror("remove address");
        return -1;
    }

    return 0;
}

static int
prepare_initstack_args(char *buff, int pid, int *fd)
{
	int current_net_ns_fd, ret, fd_dgram, bufSize, value;
	char macAddr[MACADDR_BUF_SIZE] = {0,};
	char addr4[INET_ADDRSTRLEN] = {0,};
	char gateway[GW_BUF_SIZE];
	struct ifaddrs *ifaddr, *ifa;
	sa_family_t addr_family;
	struct ifreq s;
	
	ret = 0;
	current_net_ns_fd = apply_ns(pid, CLONE_NEWNET);
	if (current_net_ns_fd < 0) {
		perror("applyns");
		return -1;
	}
    if (getifaddrs(&ifaddr) < 0) {
        perror("getifaddrs");
		ret = -1;
		goto retval;
    }
	
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        addr_family = ifa->ifa_addr->sa_family;
        if (addr_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK) && ifa->ifa_flags & IFF_UP) {
            inet_ntop(
                addr_family,
                &((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr,
                addr4,
                INET_ADDRSTRLEN
            );
			break;
        }
    }
	fd_dgram = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, ifa->ifa_name);
	if (ioctl(fd_dgram, SIOCGIFHWADDR, &s) != 0) {
		perror("ioctl");
		ret = -1;
		goto retval;
	}
	close(fd_dgram);
	for (int i=0; i<6; i++) {
		sprintf(macAddr+i*3, "%02x:", (unsigned char)s.ifr_addr.sa_data[i]);
	}
	macAddr[MACADDR_LEN] = '\0';
	if (get_gatewayip(gateway, 1024) < 0) {
		perror("get gatewayip");
		ret = -1;
		goto retval;
	}
	sprintf(buff,
		"ENV:DPDK_LO4_ENABLED=1,DPDK_IP=%s,DPDK_IP_GATEWAY=%s,DPDK_IP_MASK=%d,DPDK_MAC=%s;",
		addr4,
		gateway,
		getPrefix(((struct sockaddr_in*)(ifa->ifa_netmask))->sin_addr.s_addr),
		macAddr
	);
	*fd = socket(AF_PACKET, SOCK_RAW, 0);
	struct sockaddr_ll sk_ll = {
		.sll_family = AF_PACKET,
		.sll_protocol = 0x0300,
		.sll_ifindex = if_nametoindex(ifa->ifa_name),
		.sll_hatype = 0,
		.sll_pkttype = PACKET_OTHERHOST,
	};
	if(bind(*fd, (struct sockaddr *)&sk_ll, sizeof(sk_ll)) < 0) {
		perror("bind");
		ret = -1;
		goto retval;
	}

	bufSize = 4 << 20;
	value = 1;
	if (setsockopt(*fd, SOL_PACKET, PACKET_VNET_HDR, &value, sizeof(value)) < 0) {
		perror("setsockopt packet");
		ret = -1;
		goto retval;
	}
	if (setsockopt(*fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufSize, sizeof(bufSize)) < 0) {
		perror("setsockopt rcvsocket");
		ret = -1;
		goto retval;
	}
	if (setsockopt(*fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufSize, sizeof(bufSize)) < 0) {
		perror("setsockopt sndsocket");
		ret = -1;
		goto retval;
	}
	remove_address(ifa);

retval:
	restore_ns(current_net_ns_fd, CLONE_NEWNET);
	return ret;
}

int plugin_preinitstack(int pid, char** init_str_ptr, int **fds, int *num)
{
    *init_str_ptr = (char*)malloc(INIT_STR_LEN * sizeof(char));
	memset(*init_str_ptr, '\0', INIT_STR_LEN);
    *num = INIT_FD_NUM;

	// For virtio-user only. TODO: support virtio pci.
	*fds = (int *)malloc(INIT_FD_NUM * sizeof(int));
	(*fds)[0] = open("/dev/vhost-net", O_RDONLY);
	prepare_initstack_args(*init_str_ptr, pid, &((*fds)[1]));

	return 0;
}

static const char *random_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static void rand_str(char *str, int length)
{
	for (int i=0; i<length; i++) {
		str[i] = random_str[rte_rand() % sizeof(random_str)];
	}
}

static const char *devargs_common = "queue_size=1024,path=/dev/vhost-net";
static int build_eal_init_args(char *argv[], const char *dev_params) {
	int argc = 0;
	char vdev[VDEV_BUF_SIZE];
	char prefix[PREFIX_BUF_SIZE] = {0,};
	char file_prefix[FILE_PREFIX_SIZE];

	argv[argc++] = strdup("go");
	argv[argc++] = strdup("-l");
	argv[argc++] = strdup("0");
	argv[argc++] = strdup("--in-memory");
	rand_str(prefix, 8);
	snprintf(file_prefix, FILE_PREFIX_SIZE, "--file-prefix=%s", prefix);
	argv[argc++] = strdup(file_prefix);

	if (dev_params[0]) {
		snprintf(vdev, VDEV_BUF_SIZE, "--vdev=virtio_user0,%s,%s",
				 devargs_common, dev_params);
		argv[argc++] = strdup(vdev);
	}

	argv[argc++] = strdup("--no-pci");
	argv[argc++] = strdup("--");
	argv[argc++] = NULL;

	for (int i = 0; i < argc; i++) {
		GLUE_LOG(INFO, "arg: %d, value: %s", i, argv[i]);
	}

	return argc;
}

static void hotplug_vdev(char *dev_params)
{
	int ret;
	char devargs[VDEV_BUF_SIZE];

	snprintf(devargs, VDEV_BUF_SIZE, "%s,%s", devargs_common, dev_params);

	ret = rte_eal_hotplug_add("vdev", "virtio_user0", devargs);
	if (ret < 0)
		rte_panic("Failed to hotplug device (%s) returns %d", devargs, ret);
}

static void set_env(const char *config)
{
	char *env_start, *env_end, *start1, *end1, *start2, *end2;
	char key[INITARG_KEY_SIZE], value[INITARG_VALUE_SIZE];

	if (config == NULL)
		return;

	env_start = strchr(config, ':');
	env_end = strchr(config, ';');
	start1 = env_start;

	while(start1 < env_end && start1 != NULL) {
		start1 += 1;
		end1 = strchr(start1, '=');
		start2 = end1 + 1;
		end2 = strchr(start2, ',');
		if (end2 == NULL || end2 > env_end)
			end2 = env_end;
		strncpy(key, start1, end1-start1);
		key[end1-start1] = '\0';
		strncpy(value, start2, end2-start2);
		value[end2-start2] = '\0';
		setenv(key, value, 1);
		start1 = strchr(start1, ',');
	}
}

/*
 * Parse whatever are put by plugin_preinitstack().
 * Transfer parameters from plugin stack API mode to TLDK mode.
 */
static void parse_params_to_tldk(const char *net_config, int *fds, int num, char *dev_params)
{
	// These configs are stored in env variables and will be used in ctx init in
	// epoll_create(), aka the creation of io thread.
	if (net_config)
		set_env(net_config);

	// Generate device parameters.
	if (num > 0)
		snprintf(dev_params, DRVARGS_BUF_SIZE, "fd=%d,vhost_fd=%d,mac=%s",
				 fds[1], fds[0], getenv("DPDK_MAC"));
}

/*
 * This function will parse params and do different init:
 *
 * - Full init
 *   when preliminary_init is 0, and vdev info is ready.
 *
 * - Preliminary init:
 *   when preliminary_init is 0, and vdev info is *NOT* ready.
 *
 * - Complementary init:
 *   when preliminary_init is 1, and vdev info is ready.
 */
int plugin_initstack(const char* net_config, int *fds, int num)
{
    static int preliminary_init = 0;

	char dev_params[DRVARGS_BUF_SIZE];
	char *argv[ARGV_BUF_SIZE];
	int argc;

#ifdef TLDK_VERSION
#define QUOTE(macro) #macro
	GLUE_LOG(ERR, "TLDK version: %s", QUOTE(TLDK_VERSION));
#endif

	dev_params[0] = '\0';
	parse_params_to_tldk(net_config, fds, num, dev_params);

	GLUE_LOG(INFO, "preliminary_init: %d, net_config: %s, dev_params: %s\n",
			 preliminary_init, net_config, dev_params);

	if (preliminary_init) {
		// complementary initialization

		if (dev_params[0])
			hotplug_vdev(dev_params);

		return 0;
	}

	// preliminary or full initialization
	argc = build_eal_init_args(argv, dev_params);
	if (rte_eal_init(argc, argv) < 0)
		rte_panic("Failed to init DPDK");

	external_socket_id = create_ext_heap_socket();

	fd_init();

	timezone_offset_init();

	// The 1st invoke will init the mempool.
	get_mempool_by_socket(0);

	preliminary_init = 1;
    return 0;
}
