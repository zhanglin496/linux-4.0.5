#ifndef IP_SET_DNS_H
#define IP_SET_DNS_H

struct dnshdr
{
	u_int16_t id;
	u_int16_t flag;
	u_int16_t number_questions;
	u_int16_t number_answers;
	u_int16_t number_authority;
	u_int16_t number_additional;
};

struct dnsansip
{
	u_int16_t dns_hd;
	u_int16_t dns_type;
	u_int16_t dns_class;
	u_int16_t dns_ttl1;
	u_int16_t dns_ttl2;
	u_int16_t data_len;
	u_int32_t addr;
};
// ttl = ntohl(((u32)dns_ttl1<<16) | dns_ttl2);

/*
 * Query/response flag
 */

#define DNS_QRFLAG_QUERY        0
#define DNS_QRFLAG_RESPONSE     1

/*
 * Opcode flag
 */

#define DNS_OPCODEFLAG_STANDARD     0
#define DNS_OPCODEFLAG_INVERSE      1
#define DNS_OPCODEFLAG_STATUS       2

/*
 * Rcode (return code) flag
 */

#define DNS_RCODEFLAG_NOERROR        0
#define DNS_RCODEFLAG_FORMATERROR    1
#define DNS_RCODEFLAG_SERVERERROR    2
#define DNS_RCODEFLAG_NAMEERROR      3
#define DNS_RCODEFLAG_NOTIMPLEMENTED 4
#define DNS_RCODEFLAG_SERVICEREFUSED 5

/*
 * Query type
 */

#define DNS_QUERYTYPE_A              1
#define DNS_QUERYTYPE_NS             2
#define DNS_QUERYTYPE_CNAME          5
#define DNS_QUERYTYPE_SOA            6
#define DNS_QUERYTYPE_PTR            12
#define DNS_QUERYTYPE_HINFO          13
#define DNS_QUERYTYPE_MX             15
#define DNS_QUERYTYPE_AAAA           28
#define DNS_QUERYTYPE_AXFR           252
#define DNS_QUERYTYPE_ANY            255

/*
 * Query class
 */

#define DNS_QUERYCLASS_IP            1



#define DNS_PTR_OFFSET		     14
#define DNS_PTR_FLAG		     3
#define DNS_PTR_MASK		     0x3FFF

/* error code */
#define DNS_QUERY_OK 		0
#define DNS_QUERY_EXCEPTION	1
#define DNS_QUERY_TIMEOUT	2

#define DNS_UDP_QUERY_PORT	53


#endif
