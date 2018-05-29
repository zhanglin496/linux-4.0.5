#include <fcntl.h>  
#include <stdio.h>  
#include <string.h>  
#include <unistd.h>  
#include <linux/if_tun.h>  
#include <netinet/in.h>  
#include <sys/ioctl.h>  
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <linux/if.h>  
#include <linux/ip.h> 
#include <linux/tcp.h>
#include <stdbool.h>
#include "tun_ip.h"
 

int print_hex(char *data, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%02hhx ", (uint8_t)data[i]);
	printf("\n");
	return 0;
}

int tun_alloc(char *dev)  
{  
	struct ifreq ifr;  
	int fd, err;  

	if ((fd = open("/dev/net/tun_mmap", O_RDWR)) < 0) {  
		perror("open");  
		return -1;  
	}

	memset(&ifr, 0, sizeof(ifr));  
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
//	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  

	if (*dev) {  
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);  
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {  
		perror("ioctl");  
		close(fd);  
		return err;  
	}
	printf("tun_alloc fd=%d\n", fd);
	return fd;  
}

struct tcp_option {
	u16_t	mss_ok: 1,
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 1,	/* SACK seen on SYN packet		*/
		snd_wscale : 4;	/* Window scaling received from sender	*/
	u16_t mss;
	u32_t rcv_tsval;
	u32_t rcv_tsecr;
};

static unsigned int tcp_options_size(const struct tcp_option *opts)
{
	unsigned int size = 0;
	if (opts->mss_ok)
		size += TCPOLEN_MSS_ALIGNED;
	if (opts->tstamp_ok)
		size += TCPOLEN_TSTAMP_ALIGNED;
	if (opts->wscale_ok)
		size += TCPOLEN_WSCALE_ALIGNED;
	if (opts->sack_ok)
		size += TCPOLEN_SACK_BASE_ALIGNED;

	return size;
}

static void tcp_build_tcp_options(struct tcphdr *tph, const struct tcp_option *opts)
{
	u32_t *ptr = (u32_t *)(tph + 1);
	
	if (opts->mss_ok)
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	if (opts->tstamp_ok) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
				(TCPOPT_NOP << 16) |
				(TCPOPT_TIMESTAMP << 8) |
				TCPOLEN_TIMESTAMP);
		*ptr++ = htonl(opts->rcv_tsval);
		if (tph->syn)
			*ptr++ = 0U;
		else
			*ptr++ = htonl(opts->rcv_tsecr);
	}
	
	if (opts->wscale_ok)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->snd_wscale);

	if (opts->sack_ok)
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
}

struct tcp_data {
	struct iphdr iph;
	struct tcphdr tcph;
	char data[0];
};

#define DELCAER_TCP_DATA(x) \
	char x##_data[sizeof(struct tcp_data)+2048]__attribute__((aligned(__alignof__(struct tcp_data)))); \
	struct tcp_data *x = (void *)x##_data

static void build_iphdr(struct iphdr *iph, uint32_t saddr, uint32_t daddr)
{
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->tos = 0;
	iph->id	= 10;
	iph->frag_off = htons(IP_DF);
	iph->ttl = 64;		
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
}

static int send_syn_ack(int fd, const struct iphdr *iph, const struct tcphdr *tcph)
{
	DELCAER_TCP_DATA(e);
	struct tcp_option opts;
	struct iphdr *niph;
	struct tcphdr *ntcph;
	int hdr_size;
	memset(&opts, 0, sizeof(opts));
	opts.mss_ok = 1;
	opts.wscale_ok = 1;
	opts.snd_wscale = 7;
	opts.mss = 1440;

	niph = &e->iph;
	ntcph = &e->tcph;
	hdr_size = sizeof(*tcph) + tcp_options_size(&opts);
	build_iphdr(niph, iph->daddr, iph->saddr);
	niph->tot_len = htons(sizeof(*iph) + hdr_size);
	niph->check = inet_chksum(niph, sizeof(*niph));

	tcp_flag_word(ntcph) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (tcph->ack)
		ntcph->seq = tcph->ack_seq;
	else
		ntcph->seq = tcph->seq;
	ntcph->ack_seq = htonl(ntohl(tcph->seq) + (tcph->fin ? 1 : 0) + (tcph->syn ? 1 : 0));
	ntcph->source = tcph->dest;
	ntcph->dest = tcph->source;
	ntcph->doff = hdr_size / 4;
	ntcph->window = htons(5000);
	ntcph->urg_ptr = 0;
	ntcph->check = 0;
	tcp_build_tcp_options(ntcph, &opts);
	ntcph->check = ip_chksum_pseudo(IPPROTO_TCP, hdr_size, niph->saddr, niph->daddr, ntcph, hdr_size);

//	printf("tcp check=%x,hdr_size=%d\n", ntcph->check, hdr_size);
	write(fd, e, sizeof(*niph) + hdr_size);
	return 0;
}

static int send_http_302(int fd, const struct iphdr *iph, const struct tcphdr *tcph)
{
	DELCAER_TCP_DATA(e);
	struct iphdr *niph;
	struct tcphdr *ntcph;
	int len;
	int hdr_size = sizeof(*tcph);

	niph = &e->iph;
	ntcph = &e->tcph;
	build_iphdr(niph, iph->daddr, iph->saddr);

	len = snprintf(e->data, 2048, "HTTP/1.1 302 Found\r\n"
			"Content-Length: 0\r\n"
			"Connection: close\r\n"
			"Server: nginx/1.8.0\r\n"
			"Content-Type: text/html\r\n"
			"Location: %s\r\n"
			"Pragma: no-cache\r\n"
			"Cache-Control: no-cache\r\n\r\n", "http://www.qq.com");

	niph->tot_len = htons(sizeof(*iph) + hdr_size + len);
	niph->check = inet_chksum(niph, sizeof(*niph));

	tcp_flag_word(ntcph) = TCP_FLAG_ACK | TCP_FLAG_FIN;
	if (tcph->ack)
		ntcph->seq = tcph->ack_seq;
	else
		ntcph->seq = tcph->seq;
	ntcph->ack_seq = htonl(ntohl(tcph->seq) + ntohs(iph->tot_len) -
					iph->ihl*4 - tcph->doff*4 + (tcph->fin ? 1 : 0) + (tcph->syn ? 1 : 0));
	ntcph->source = tcph->dest;
	ntcph->dest = tcph->source;
	ntcph->doff = hdr_size / 4;
	ntcph->window = htons(5000);
	ntcph->urg_ptr = 0;
	ntcph->check = 0;

	ntcph->check = ip_chksum_pseudo(IPPROTO_TCP, hdr_size + len, niph->saddr, niph->daddr, ntcph, hdr_size + len);
	write(fd, e, sizeof(*e) + len);
	return 0;
}

static int send_rst(int fd, const struct iphdr *iph, const struct tcphdr *tcph)
{
	DELCAER_TCP_DATA(e);
	struct iphdr *niph;
	struct tcphdr *ntcph;
	int hdr_size = sizeof(*tcph);

	niph = &e->iph;
	ntcph = &e->tcph;
	build_iphdr(niph, iph->daddr, iph->saddr);

	niph->tot_len = htons(sizeof(*niph) + hdr_size);
	niph->check = inet_chksum(niph, sizeof(*niph));
	tcp_flag_word(ntcph) = TCP_FLAG_ACK | TCP_FLAG_RST;
	if (tcph->ack)
		ntcph->seq = tcph->ack_seq;
	else
		ntcph->seq = tcph->seq;
	ntcph->ack_seq = htonl(ntohl(tcph->seq) + (tcph->fin ? 1 : 0) + (tcph->syn ? 1 : 0));
	ntcph->source = tcph->dest;
	ntcph->dest = tcph->source;
	ntcph->doff = hdr_size / 4;
	ntcph->window = htons(5000);
	ntcph->urg_ptr = 0;
	ntcph->check = 0;
	ntcph->check = ip_chksum_pseudo(IPPROTO_TCP, hdr_size, niph->saddr, niph->daddr, ntcph, hdr_size);
	write(fd, e, sizeof(*e));

	return 0;
}

int tcp_state_process(int fd, const struct iphdr *iph)
{
	struct tcphdr *tcph = (void *)iph + iph->ihl*4;
	int len = iph->ihl*4 + tcph->doff*4;

//	printf("src="NIPQUAD_FMT",dst="NIPQUAD_FMT"\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
	if (tcph->syn) {
		send_syn_ack(fd, iph, tcph);
	} else if (tcph->fin) {
		send_rst(fd, iph, tcph);
	} else if (tcph->ack) {
		if (ntohs(iph->tot_len) > len)
			send_http_302(fd, iph, tcph);
	}

	return 0;
}

static bool ip_is_valid(const struct iphdr *iph, int nr)
{
	struct tcphdr *tcph;
	if (nr < sizeof(*iph) + sizeof(*tcph))
		return false;
	if (ntohs(iph->tot_len) > nr)
		return false;
	if (iph->ihl*4 < sizeof(*iph))
		return false;
	nr -= iph->ihl;
	if (nr <= sizeof(*tcph))
		return false;

	tcph = (void *)iph + iph->ihl*4;
	if (tcph->doff*4 < sizeof(*tcph))
		return false;

	return true;
}

extern int tpacket(int fd);

int main()
{
	int nr;
	char buf[2048];
	int fd = tun_alloc("tap0");
	if (fd < 0)
		return -1;

	while (1)
		tpacket(fd);

	while (1) {
		nr = read(fd, buf, sizeof(buf));
		if (nr <= 0)
			continue;

		struct iphdr *iph = (void *)buf;
		
		if (!ip_is_valid(iph, nr))
			continue;

		printf("nr =%d,totel_len=%u,ck_sum=%u\n", nr, ntohs(iph->tot_len), inet_chksum(buf, iph->ihl*4));
		printf("src="NIPQUAD_FMT",dst="NIPQUAD_FMT"\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
		tcp_state_process(fd, iph);
	}
	return 0;
}

