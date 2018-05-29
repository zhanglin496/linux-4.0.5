#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <errno.h>

#ifndef likely 
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

#define FRAME_SIZE (1<<11)

//每个块的起始头部，和内核实现相对应
struct block_desc {
//	uint32_t version;
//	uint32_t offset_to_priv;
	struct tpacket_hdr h1; 
};

struct ring {
	struct iovec *rd;
	uint8_t *map;
	struct tpacket_req req; 
};

#define TUN_PACKET_RX_RING _IOW('T', 224, union tpacket_req_u)

struct ring ring;
static unsigned long packets_total = 0, bytes_total = 0; static sig_atomic_t sigint = 0;

static void sighandler(int num)
{ 
	sigint = 1; 
}

static int setup_socket(struct ring *ring, int fd)
{
	int err, i;
	unsigned int blocksiz = 1 << 16; //	64KB
	unsigned int framesiz = 1 << 11;
	unsigned int blocknum = 64; //64KB*64

	
	printf("blocksiz=%u,framesiz=%u,blocknum=%u\n", blocksiz, framesiz, blocknum);
	memset(&ring->req, 0, sizeof(ring->req));
	ring->req.tp_block_size = blocksiz;
	ring->req.tp_frame_size = framesiz;
	ring->req.tp_block_nr = blocknum;
	ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;

	if ((err = ioctl(fd, TUN_PACKET_RX_RING, (void *) &ring->req)) < 0) {
		printf("TUN_PACKET_RX_RING ioctl error, errno=%d\n", errno);
		exit(1);
	}
	//映射内核空间到用户空间
	ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
	if (ring->map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

//	mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);

	ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
	assert(ring->rd);

	for (i = 0; i < ring->req.tp_block_nr; ++i) {
		//记录块起始地址
		ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
		//记录块长度
		ring->rd[i].iov_len = ring->req.tp_block_size;
	}
	printf("setup_socket success\n");
	return 0;
}

#define MAC2_FMT "%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX"
#define MAC_ARG(x) ((uint8_t*)(x))[0],((uint8_t*)(x))[1],((uint8_t*)(x))[2],((uint8_t*)(x))[3],((uint8_t*)(x))[4],((uint8_t*)(x))[5]

static void display(struct tpacket_hdr *ppd)
{
	//获取mac头指针
//	struct ethhdr *eth = (struct ethhdr *)((uint8_t *)ppd + ppd->tp_mac);
	struct iphdr *ip = (struct iphdr *)((uint8_t *)ppd + ppd->tp_mac);
	//获取ip头部指针
//	struct iphdr *ip = (struct iphdr *)((uint8_t *)eth + ETH_HLEN);
	printf("version=%d, len=%u\n", ip->version, ppd->tp_snaplen);
	{
		struct sockaddr_in ss, sd;
		char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];
		memset(&ss, 0, sizeof(ss));
		ss.sin_family = PF_INET;
		ss.sin_addr.s_addr = ip->saddr;
		//源ip转换成字符串
		getnameinfo((struct sockaddr *)&ss, sizeof(ss), sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);
		memset(&sd, 0, sizeof(sd));
		sd.sin_family = PF_INET;
		sd.sin_addr.s_addr = ip->daddr;
		//目的ip转换成字符串
		getnameinfo((struct sockaddr *) &sd, sizeof(sd), dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);
		printf("snapelen %d, len %d, %s -> %s\n", ppd->tp_snaplen, ppd->tp_len, sbuff, dbuff);
	}
//	printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);
}

static void print_hex(unsigned char *data, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%02hhx ", data[i]);
	printf("\n\n");
}

//遍历一个block的所有frame
static void walk_block(int fd, struct block_desc **pbd, int *block_num, int *tp_frame_nr)
{
//	int num_pkts = pbd->h1.num_pkts, i;
	unsigned long bytes = 0;
	struct tpacket_hdr *ppd;
	int i;

	//每个帧都是tpacket3_hdr开头
	ppd = (struct tpacket_hdr *)((uint8_t *)*pbd);

	for (i = 0; *tp_frame_nr;) {
//		ppd = (void *)ppd + i*ring.req.tp_frame_size;
		bytes += ppd->tp_snaplen;
//		printf("block_num=%d, i=%d, nr=%d, ppd=%p,status=%u,sec=%u\n", *block_num, i, *tp_frame_nr, ppd, ppd->tp_status, ppd->tp_sec);
//		print_hex((void *)pbd, ring.req.tp_block_size);
//		exit(0);
		if (ppd->tp_status == TP_STATUS_KERNEL) {
			*pbd = ppd;
//			ppd = (void *)pbd + i*ring.req.tp_frame_size;
			return;
		}
//		display(ppd);
		(*tp_frame_nr)--;
		ppd->tp_status = TP_STATUS_KERNEL;
		ppd->tp_len = 0;
		tcp_state_process(fd, (uint8_t *)ppd + ppd->tp_mac);
		ppd = (void *)ppd + ring.req.tp_frame_size;

//		barrier();
//		ppd = (void *)pbd + i*ring.req.tp_frame_size;
	}
	*pbd = ppd;

//	*block_num++;
//	*block_num %= 64;
//	*tp_frame_nr =  ring.req.tp_block_nr / ring.req.tp_frame_size
//	packets_total += num_pkts;
//	bytes_total += bytes;
}

//这个块已经读取完毕，通知内核可以重新使用
static void flush_block(struct block_desc *pbd)
{
	pbd->h1.tp_status = TP_STATUS_KERNEL;
}

static void teardown_socket(struct ring *ring, int fd)
{
	munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
	free(ring->rd);
	close(fd);
}

int tpacket(int fd)
{
	int err;
	struct pollfd pfd;
	unsigned int block_num = 0, blocks = 64;
	struct block_desc *pbd;
#if 0
	struct tpacket_stats_v3 stats;


	if (argc != 2) {
		fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
		return EXIT_FAILURE;
	}
#endif
	signal(SIGINT, sighandler);
	memset(&ring, 0, sizeof(ring));
	setup_socket(&ring, fd);
	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;
	printf("fd=%d\n", fd);

	pbd = (struct block_desc *) ring.rd[block_num].iov_base;
	int tp_frame_nr =  ring.req.tp_block_size / ring.req.tp_frame_size;
	while (likely(!sigint)) {
//		pbd = (struct block_desc *) ring.rd[block_num].iov_base;
		//内核是按顺序存放数据到block，所以当前block没有数据
		//那么后面的block一定没有数据
		//循环检查当前block是否有数据
		if ((pbd->h1.tp_status & TP_STATUS_USER) == 0) {
		//	printf("poll wait\n");		
			poll(&pfd, 1, -1);
			continue;
		}
		printf("walk_block, tp_frame_nr=%d\n", tp_frame_nr);
		walk_block(fd, &pbd, &block_num, &tp_frame_nr);
		if (!tp_frame_nr) {
		//取下一个block
			printf("block_num %d is clear\n", block_num);
			block_num = (block_num + 1) % blocks;
			pbd = (struct block_desc *) ring.rd[block_num].iov_base;
			tp_frame_nr =  ring.req.tp_block_size / ring.req.tp_frame_size;
		}
	}
#if 0
	len = sizeof(stats);
	err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	if (err < 0) {
		perror("getsockopt");
		exit(1);
	}

	fflush(stdout);
	printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n", stats.tp_packets, bytes_total, stats.tp_drops,
	       stats.tp_freeze_q_cnt);
#endif
	teardown_socket(&ring, fd);
	return 0;
}


