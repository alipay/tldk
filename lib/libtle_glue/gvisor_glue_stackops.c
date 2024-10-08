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
#include <linux/version.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gvisor_glue.h"
#include "tle_glue.h"
#include "util.h" 
#include "init.h"
#include "internal.h"

#define INIT_STR_LEN 2048
#define INIT_FD_NUM 2

#define INTERFACE_STR_LEN 1024
#define INTERFACE_ADDR_STR_LEN 1024
#define NETLINK_RESPONSE_LEN 2048
#define ROUTES_STR_LEN 1024
#define PORT_RANGE_STR_LEN 64

#define RAW_STR_LEN 64
#define JSON_STR_LEN 512

#define NS_PATH_BUF_SIZE 80

#define MACADDR_BUF_SIZE 20
#define MACADDR_LEN 17
#define GW_BUF_SIZE 1024
#define IF_INFO_SIZE 1024

#define ARGV_BUF_SIZE 16
#define VDEV_BUF_SIZE 120
#define DRVARGS_BUF_SIZE 100
#define PREFIX_BUF_SIZE 11
#define FILE_PREFIX_SIZE 30
#define INITARG_KEY_SIZE 20
#define INITARG_VALUE_SIZE 200

#define IFA_STRUCT_FORMAT "{\"Family\":%d,\"PrefixLen\":%d,\"Flags\":%d,\"Addr\":[%d,%d,%d,%d]}"
#define IF_STRUCT_FORMAT "{\"DeviceType\":%d,\"Flags\":%d,\"Name\":\"%s\",\"Addr\":[%d,%d,%d,%d,%d,%d],\"MTU\":%d}"
#define ROUTE_STRUCT_FORMAT "{\"Family\":%d,\"DstLen\":%d,\"Protocol\":%d,\"Scope\":%d,\"Type\":%d,\"DstAddr\":[%d,%d,%d,%d],\"OutputInterface\":%d,\"GatewayAddr\":[%d,%d,%d,%d]}"
#define TCP_BUF_SIZE_STRUCT_FORMAT "{\"Min\": %d,\"Default\":%d,\"Max\":%d}"

#define LO_IF_IDX 1
#define ETH0_IF_IDX 2

#define LO_IF_NAME "lo"
#define LO_IF_FLAGS (IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP)
#define LO_IF_MTU 65536
#define LO_IFA_PREFIX 8

#define MIN_TCP_BUF_SIZE 4096
#define MAX_TCP_BUF_SIZE 212992

#define DEFAULT_MIN_PORT 32768
#define DEFAULT_MAX_PORT 60999

const uint8_t LO_IF_MAC_ADDR[] = {0, 0, 0, 0, 0, 0};
const uint8_t LO_IFA_IP_ADDR[] = {127, 0, 0, 1};

struct plugin_interface {
	uint16_t device_type;
	uint32_t flags;
	char name[32];
	unsigned char addr[6];
	uint32_t mtu;
};

struct plugin_interface_addr_v4 {
	uint8_t family;
	uint8_t prefix_len;
	uint8_t flags;
	unsigned char addr[4];
};

struct plugin_interface *plugin_if;
struct plugin_interface_addr_v4 *plugin_ifa;

static int
get_gateway_ip(char *gatewayip, socklen_t size)
{
	char buffer[256];  // Line buffer
    char iface[16];    // Interface name
    char dest[9];      // Destination address
    char gateway[9];   // Gateway address (this is what we're looking for)
    int found_default = 0;
	unsigned char gw[4];

    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) {
        GLUE_LOG(ERR, "Error opening /proc/net/route");
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	case CLONE_NEWCGROUP:
		return "cgroup";
#endif
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
		GLUE_LOG(ERR, "failed to create socket for remove address");
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
        GLUE_LOG(ERR, "failed to remove address");
        return -1;
    }

    return 0;
}

/*
 * Get eth0 interface address information from current netns
 * and marshal it into string with format: family|prefix|flags|addr .
 * This string will be used in init_str to pass argument for stack
 * initialization.
 */
static int
get_interface_addr_raw_str(struct ifaddrs **eth0_ifa, char *buf)
{
	struct ifaddrs *ifaddr, *ifa;
	char addr4[INET_ADDRSTRLEN] = {0,};
	sa_family_t addr_family;
	int ret = 0;

	if (getifaddrs(&ifaddr) < 0) {
		GLUE_LOG(ERR, "failed to getifaddrs in get_interface_addr");
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

	if (!ifa) {
		GLUE_LOG(ERR, "failed to find eth0 interface");
		ret = -1;
		goto retval;
	}

	*eth0_ifa = ifa;
	addr_family = ifa->ifa_addr->sa_family;
    inet_ntop(
        addr_family,
        &((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr,
        addr4,
        INET_ADDRSTRLEN
    );

	// Build up interface address string in format: family|prefix|flags|addr
	sprintf(buf, "%d|%d|%u|%s",
		addr_family,
		getPrefix(((struct sockaddr_in*)(ifa->ifa_netmask))->sin_addr.s_addr),
		ifa->ifa_flags,
		addr4
	);

retval:
	return ret;
}

/*
 * Get eth0 interface information from current netns
 * and marshal it into string with format: name|mac_addr|device_type|mtu|flags .
 * This string will be used in init_str to pass argument for stack
 * initialization.
 */
static int
get_interface_raw_str(char *ifname, char *buf)
{
	char macAddr[MACADDR_BUF_SIZE] = {0,};
	int s, device_type, mtu;
	unsigned short flags;
	struct ifreq ifr;

	// Create a socket to communicate with the kernel.
	s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (s < 0) {
		GLUE_LOG(ERR, "Unable to open socket");
		return -1;
	}

	strcpy(ifr.ifr_name, ifname);

	// Execute the operation to retrieve the hardware (MAC) address.
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		GLUE_LOG(ERR, "ioctl failed");
		close(s);
		return -1;
	}

	// Get the MAC address.
	for (int i=0; i<6; i++) {
		sprintf(macAddr+i*3, "%02x:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	}
	macAddr[MACADDR_LEN] = '\0';
	device_type = ifr.ifr_hwaddr.sa_family;

    // Get the MTU.
    if (ioctl(s, SIOCGIFMTU, &ifr) < 0) {
        GLUE_LOG(ERR, "ioctl SIOCGIFMTU failed");
        close(s);
        return -1;
    }
	mtu = ifr.ifr_mtu;

    // Get the interface flags.
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        GLUE_LOG(ERR, "ioctl SIOCGIFFLAGS failed");
        close(s);
        return -1;
    }
	flags = ifr.ifr_flags;

	// Close the socket.
	close(s);

	// Save interface information in format: name|mac_addr|device_type|mtu|flags
	sprintf(buf, "%s|%s|%d|%d|%u", ifname, macAddr, device_type, mtu, flags);
	return 0;
}

static int
prepare_initstack_args(char *buff, int pid, int *fd)
{
	int current_net_ns_fd, ret, bufSize, value;
	char if_buf[RAW_STR_LEN] = {0,};
	char ifa_buf[RAW_STR_LEN] = {0,};
	char gateway_ip[GW_BUF_SIZE];
	struct ifaddrs *ifa;

	ret = 0;
	current_net_ns_fd = apply_ns(pid, CLONE_NEWNET);
	if (current_net_ns_fd < 0) {
		GLUE_LOG(ERR, "failed to apply ns");
		return -1;
	}

	// 1. prepare interface address info in raw string format: family|prefix|flags|addr
	if (get_interface_addr_raw_str(&ifa, ifa_buf) < 0 || !ifa) {
		GLUE_LOG(ERR, "failed get interface addr in raw str format");
		ret = -1;
		goto retval;
	}

	// 2. prepare interface info in raw string format: name|mac_addr|device_type|mtu|flags
	if (get_interface_raw_str(ifa->ifa_name, if_buf) < 0) {
		GLUE_LOG(ERR, "failed to get interface in raw str format");
		ret = -1;
		goto retval;
	}

	// 3. prepare default gateway ip
	if (get_gateway_ip(gateway_ip, 1024) < 0) {
		GLUE_LOG(ERR, "failed to get default gateway ip");
		ret = -1;
		goto retval;
	}

	// 4. build up environment variables argument string
	sprintf(buff,
		"ENV:DPDK_LO4_ENABLED=1,DPDK_IF=%s,DPDK_IFA=%s,DPDK_IP_GATEWAY=%s;",
		if_buf,
		ifa_buf,
		gateway_ip
	);

	// 5. prepare interface configuration for dpdk
	*fd = socket(AF_PACKET, SOCK_RAW, 0);
	struct sockaddr_ll sk_ll = {
		.sll_family = AF_PACKET,
		.sll_protocol = 0x0300,
		.sll_ifindex = if_nametoindex(ifa->ifa_name),
		.sll_hatype = 0,
		.sll_pkttype = PACKET_OTHERHOST,
	};
	if(bind(*fd, (struct sockaddr *)&sk_ll, sizeof(sk_ll)) < 0) {
		GLUE_LOG(ERR, "failed to bind socket");
		ret = -1;
		goto retval;
	}

	bufSize = 4 << 20;
	value = 1;
	if (setsockopt(*fd, SOL_PACKET, PACKET_VNET_HDR, &value, sizeof(value)) < 0) {
		GLUE_LOG(ERR, "failed to setsockopt packet");
		ret = -1;
		goto retval;
	}
	if (setsockopt(*fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufSize, sizeof(bufSize)) < 0) {
		GLUE_LOG(ERR, "failed to setsockopt rcvsocket");
		ret = -1;
		goto retval;
	}
	if (setsockopt(*fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufSize, sizeof(bufSize)) < 0) {
		GLUE_LOG(ERR, "failed to setsockopt sndsocket");
		ret = -1;
		goto retval;
	}

	// 5. remove interface from netns
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
	return prepare_initstack_args(*init_str_ptr, pid, &((*fds)[1]));
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

/*
 * Function to convert an MAC address string into a byte array.
 */
static void
parse_mac_addr(const char *mac_str, unsigned char *addr) {
    int tmp[6]; // Temporary array to hold the parsed MAC bytes
    sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i = 0; i < 6; i++) {
        addr[i] = (unsigned char) tmp[i];
    }
}

/*
 *	Function to convert an IPv4 address string into a byte array.
 */
static void
parse_ip4_addr(const char *ip_str, unsigned char *addr) {
    int tmp[4]; // Temporary array to hold the parsed IP bytes
    sscanf(ip_str, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
    for(int i = 0; i < 4; i++) {
        addr[i] = (unsigned char) tmp[i];
    }
}

/*
 * Parse interface information from string with format: name|mac_addr|device_type|mtu|flags
 * and store in global variable plugin_if, which will be read during plugin_get_interfaces.
 * Besides, during parsing interface information, this function will also set env: DPDK_MAC.
 */
static int parse_interface_from_raw(char *raw_str)
{
	if (!plugin_if)
		plugin_if = (struct plugin_interface *)malloc(sizeof(struct plugin_interface));

	memset(plugin_if->name, '\0', 32);

	char *token = strtok(raw_str, "|");
	sprintf(plugin_if->name, "%s", token);

	token = strtok(NULL, "|");
	parse_mac_addr(token, plugin_if->addr);

	// Set DPDK_MAC env.
	setenv("DPDK_MAC", token, 1);

	token = strtok(NULL, "|");
	plugin_if->device_type = atoi(token) & 0xFFFF;

	token = strtok(NULL, "|");
	plugin_if->mtu = atoi(token);

	token = strtok(NULL, "|");
	plugin_if->flags = atoi(token);

	return 0;
}

/*
 * Parse interface address information from string with format: family|prefix|flags|addr
 * and store in global variable plugin_ifa, which will be read during plugin_get_interfaceaddrs.
 * Besides, during parsing interface address information, this function will also set env:
 * DPDK_IP and DPDK_IP_MASK.
 */
static int parse_interface_addr_from_raw(char *raw_str)
{
	if (!plugin_ifa)
		plugin_ifa = (struct plugin_interface_addr_v4 *)malloc(sizeof(struct plugin_interface_addr_v4));

	char *token = strtok(raw_str, "|");
	plugin_ifa->family = atoi(token);

	token = strtok(NULL, "|");
	plugin_ifa->prefix_len = atoi(token);
	// Set DPDK_IP_MASK env.
	setenv("DPDK_IP_MASK", token, 1);

	token = strtok(NULL, "|");
	// Only need lower 8-bit of flags.
	plugin_ifa->flags = atoi(token) & 0xFF;

	if (plugin_ifa->family != AF_INET) {
		GLUE_LOG(ERR, "only support IPv4 for now");
		return -1;
	}

	token = strtok(NULL, "|");
	parse_ip4_addr(token, plugin_ifa->addr);

	// Set DPDK_IP env.
	setenv("DPDK_IP", token, 1);

	return 0;
}

/*
 * Parse net configurations from stack init_str.
 * DPDK_IF and DPDK_IFA will be stored as global variables,
 * while other arguments will be set as environment variables.
 */
static void parse_net_config(const char *config)
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
		if (strcmp(key, "DPDK_IF") == 0) {
			// Store DPDK_IF as global variable plugin_if.
			parse_interface_from_raw(value);
		} else if (strcmp(key, "DPDK_IFA") == 0) {
			// Store DPDK_IFA as global variable plugin_ifa.
			parse_interface_addr_from_raw(value);
		} else {
			setenv(key, value, 1);
		}
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
		parse_net_config(net_config);

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

void plugin_destroystack(void) {
	/* TODO: lets optimize it */
	kill_tcp_streams();
}

/*
 * Build up interfaces map in json format.
 */
static void
build_interface_map(char **interfaces) {
	char *if_lo_json, *if_eth0_json;

	if_lo_json = (char*)malloc(JSON_STR_LEN * sizeof(char));
	memset(if_lo_json, '\0', JSON_STR_LEN);

	if_eth0_json = (char*)malloc(JSON_STR_LEN * sizeof(char));
	memset(if_eth0_json, '\0', JSON_STR_LEN);

	sprintf(if_lo_json, IF_STRUCT_FORMAT,
		ARPHRD_LOOPBACK,
		LO_IF_FLAGS & 0xFF,
		LO_IF_NAME,
		LO_IF_MAC_ADDR[0], LO_IF_MAC_ADDR[1], LO_IF_MAC_ADDR[2], LO_IF_MAC_ADDR[3], LO_IF_MAC_ADDR[4], LO_IF_MAC_ADDR[5],
		LO_IF_MTU);

	sprintf(if_eth0_json, IF_STRUCT_FORMAT,
		plugin_if->device_type,
		plugin_if->flags,
		plugin_if->name,
		plugin_if->addr[0], plugin_if->addr[1], plugin_if->addr[2], plugin_if->addr[3], plugin_if->addr[4], plugin_if->addr[5],
		plugin_if->mtu);

	sprintf(*interfaces, "{\"%d\":%s, \"%d\":%s}",
		LO_IF_IDX, if_lo_json, ETH0_IF_IDX, if_eth0_json);

	free(if_lo_json);
	free(if_eth0_json);
}

/*
 * Get all interfaces information including eth0 and loopback device.
 * Return interface in JSON format as map[int32][]inet.InterfaceAddr.
 */
int plugin_get_interfaces(char **interfaces) {
	// This allocation will be freed in Go.
	*interfaces = (char*)malloc(INTERFACE_STR_LEN * sizeof(char));
	memset(*interfaces, '\0', INTERFACE_STR_LEN);

	// Add dpdk interface information.
	build_interface_map(interfaces);

	return 0;
}

static void
build_interface_addr_map(char **interface_addrs) {
	char *ifa_lo_json, *ifa_eth0_json;

	ifa_lo_json = (char*)malloc(JSON_STR_LEN * sizeof(char));
	memset(ifa_lo_json, '\0', JSON_STR_LEN);

	ifa_eth0_json = (char*)malloc(JSON_STR_LEN * sizeof(char));
	memset(ifa_eth0_json, '\0', JSON_STR_LEN);

	// Build up lo interface address JSON string.
	sprintf(ifa_lo_json, IFA_STRUCT_FORMAT,
		AF_INET,
		LO_IFA_PREFIX,
		IFA_F_PERMANENT,
		LO_IFA_IP_ADDR[0], LO_IFA_IP_ADDR[1], LO_IFA_IP_ADDR[2], LO_IFA_IP_ADDR[3]);

	// Build up eth0 interface address JSON string.
	sprintf(ifa_eth0_json, IFA_STRUCT_FORMAT,
		plugin_ifa->family,
		plugin_ifa->prefix_len,
		plugin_ifa->flags,
		plugin_ifa->addr[0], plugin_ifa->addr[1], plugin_ifa->addr[2], plugin_ifa->addr[3]);

	sprintf(*interface_addrs, "{\"%d\":[%s], \"%d\":[%s]}",
		LO_IF_IDX, ifa_lo_json, ETH0_IF_IDX, ifa_eth0_json);

	free(ifa_lo_json);
	free(ifa_eth0_json);
}

/*
 * Get all interface addresses including eth0 and loopback device.
 * Return interface address in JSON format as map[int32]inet.Interface.
 */
int plugin_get_interfaceaddrs(char **interface_addrs) {
	// This allocation will be freed in Go.
	*interface_addrs = (char*)malloc(INTERFACE_ADDR_STR_LEN * sizeof(char));
	memset(*interface_addrs, '\0', INTERFACE_ADDR_STR_LEN);

	build_interface_addr_map(interface_addrs);
	return 0;
}

static inline uint8_t
convert_netmask_to_len(in_addr_t mask)
{
	uint8_t length = 0;

	mask = ntohl(mask);
	while (mask) {
		length += mask & 1;
		mask >>= 1;
	}

	return length;
}

/*
 * Get all routes information in current netns.
 * Return routes string in JSON format as list of inet.Route.
 */
int plugin_get_routes(char **routes) {
	unsigned char dst_addr[4], gw_addr[4];
	struct in_addr route_dst, route_gw;
	struct route_entry *entry;
	char *route;

	// This allocation will be freed in Go.
	*routes = (char*)malloc(ROUTES_STR_LEN * sizeof(char));
	memset(*routes, '\0', ROUTES_STR_LEN);

	route = (char *)malloc(JSON_STR_LEN * sizeof(char));
	memset(route, '\0', JSON_STR_LEN);

	sprintf(*routes, "%s", "[");

	if (default_ctx->ipv4_rt.cnt == 0)
		return 0;

	rte_rwlock_read_lock(&(default_ctx->ipv4_rt.lock));
	STAILQ_FOREACH(entry, &(default_ctx->ipv4_rt.head), link) {
		route_dst.s_addr = entry->dst;
		route_gw.s_addr = entry->gw;

		parse_ip4_addr(inet_ntoa(route_dst), dst_addr);
		parse_ip4_addr(inet_ntoa(route_gw), gw_addr);

		// build route json str from route entry struct
		sprintf(route, ROUTE_STRUCT_FORMAT,
			AF_INET,
			convert_netmask_to_len(entry->mask),
			RTPROT_KERNEL,
			RT_SCOPE_HOST,
			RTN_UNICAST,
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3],
			0,
			gw_addr[0], gw_addr[1], gw_addr[2], gw_addr[3]);

		// add ',' as seperator if it is not the first route info.
		if (strcmp(*routes, "[") != 0) {
			strcat(*routes, ",");
		}
		strcat(*routes, route);
		memset(route, '\0', JSON_STR_LEN);
	}
	rte_rwlock_read_unlock(&(default_ctx->ipv4_rt.lock));

	strcat(*routes, "]");
	free(route);

	return 0;
}

int plugin_add_route(in_addr_t dst, uint8_t dst_len, in_addr_t gw) {
	return v_route_add(dst, dst_len, gw);
}

int plugin_del_route(in_addr_t dst, uint8_t dst_len, in_addr_t gw) {
	return v_route_del(dst, dst_len, gw);
}

int plugin_get_tcp_sndbuf_size(char **sndbuf_size) {
	*sndbuf_size = (char *)malloc(JSON_STR_LEN * sizeof(char));
	memset(*sndbuf_size, '\0', JSON_STR_LEN);

	sprintf(*sndbuf_size, TCP_BUF_SIZE_STRUCT_FORMAT,
		MIN_TCP_BUF_SIZE,
		MAX_TCP_BUF_SIZE,
		MAX_TCP_BUF_SIZE);

	return 0;
}

int plugin_get_tcp_rcvbuf_size(char **rcvbuf_size) {
	*rcvbuf_size = (char *)malloc(JSON_STR_LEN * sizeof(char));
	memset(*rcvbuf_size, '\0', JSON_STR_LEN);

	sprintf(*rcvbuf_size, TCP_BUF_SIZE_STRUCT_FORMAT,
		MIN_TCP_BUF_SIZE,
		MAX_TCP_BUF_SIZE,
		MAX_TCP_BUF_SIZE);

	return 0;
}

int plugin_get_port_range(char **port_range) {
	*port_range = (char *)malloc(PORT_RANGE_STR_LEN * sizeof(char));
	memset(*port_range, '\0', PORT_RANGE_STR_LEN);

	sprintf(*port_range, "%d,%d", DEFAULT_MIN_PORT, DEFAULT_MAX_PORT);

	return 0;
}
