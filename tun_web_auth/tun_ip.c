#include <stdint.h>
#include <arpa/inet.h>
#include "tun_ip.h"

#define LWIP_CHKSUM lwip_standard_chksum

#define FOLD_U32T(u)          (((u) >> 16) + ((u) & 0x0000ffffUL))
#define SWAP_BYTES_IN_WORD(w) (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8)

uint16_t
in_cksum(uint16_t *addr, int len)
{
	int				nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
 	 * carry bits from the top 16 bits into the lower 16 bits.
 	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

	/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

static u16_t lwip_standard_chksum(const void *dataptr, int len)
{
	u32_t acc;
	u16_t src;
	const u8_t *octetptr;

	acc = 0;
	/* dataptr may be at odd or even addresses */
	octetptr = (const u8_t*)dataptr;
	while (len > 1) {
		/* declare first octet as most significant
		thus assume network order, ignoring host order */
		src = (*octetptr) << 8;
		octetptr++;
		/* declare second octet as least significant */
		src |= (*octetptr);
		octetptr++;
		acc += src;
		len -= 2;
	}
	if (len > 0) {
		/* accumulate remaining octet */
		src = (*octetptr) << 8;
		acc += src;
	}
	/* add deferred carry bits */
	acc = (acc >> 16) + (acc & 0x0000ffffUL);
	if ((acc & 0xffff0000UL) != 0) {
		acc = (acc >> 16) + (acc & 0x0000ffffUL);
	}
	/* This maybe a little confusing: reorder sum using lwip_htons()
	 instead of lwip_ntohs() since it has a little less call overhead.
	 The caller must invert bits for Internet sum ! */
	return htons((u16_t)acc);
}

u16_t inet_chksum(const void *dataptr, u16_t len)
{
	return (u16_t)~(unsigned int)LWIP_CHKSUM(dataptr, len);
}


/** Parts of the pseudo checksum which are common to IPv4 and IPv6 */
static u16_t
inet_cksum_pseudo_base(u8_t proto, u16_t proto_len, u32_t acc, void *data, int data_len)
{
	u8_t swapped = 0;

	acc += LWIP_CHKSUM(data, data_len);
	acc = FOLD_U32T(acc);

	if (data_len % 2 != 0) {
		swapped = 1 - swapped;
		acc = SWAP_BYTES_IN_WORD(acc);
	}

	if (swapped) {
		acc = SWAP_BYTES_IN_WORD(acc);
	}

	acc += (u32_t)htons((u16_t)proto);
	acc += (u32_t)htons(proto_len);

	/* Fold 32-bit sum to 16 bits
	calling this twice is probably faster than if statements... */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);
	return (u16_t)~(acc & 0xffffUL);
}

static u16_t inet_chksum_pseudo(u8_t proto, u16_t proto_len,
       const uint32_t src, const uint32_t dest, void *data, int data_len)
{
	u32_t acc;
	u32_t addr;

	addr = src;
	acc = (addr & 0xffffUL);
	acc += ((addr >> 16) & 0xffffUL);
	addr = dest;
	acc += (addr & 0xffffUL);
	acc += ((addr >> 16) & 0xffffUL);
	/* fold down to 16 bits */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);

	return inet_cksum_pseudo_base(proto, proto_len, acc, data, data_len);
}

u16_t ip_chksum_pseudo(u8_t proto, u16_t proto_len,
       const uint32_t src, const uint32_t dest, void *data, int data_len)
{
	return inet_chksum_pseudo(proto, proto_len, src, dest, data, data_len);
}
