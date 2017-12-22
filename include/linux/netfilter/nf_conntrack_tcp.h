#ifndef _NF_CONNTRACK_TCP_H
#define _NF_CONNTRACK_TCP_H

#include <uapi/linux/netfilter/nf_conntrack_tcp.h>


struct ip_ct_tcp_state {
//以下值都是根据相应条件动态变化的
//之所以都要记录最大值，是因为数据包的
//到达可能乱序，为了防止错误的丢弃
//合法的数据包，使用最大值来增加
//系统的容错能力


//连接项中当前有效ACK边界的确立：
//因为A不可能为其未收到的数据进行确认，
//所以报文中的ACK不可能大于其所收到报文的最大SEQ，
//所以有效ACK的上限为：
//A ：ack <= B ：max{ seq + len}  
//记录该连接曾经发送的最大数据包结束序列号值
	u_int32_t	td_end;		/* max of seq + len */
//记录该连接曾经收到的最大可以接收的ack 字节序列号值
	u_int32_t	td_maxend;	/* max of ack + max(win, 1) */
//记录该连接曾经收到最大通告窗口值
	u_int32_t	td_maxwin;	/* max(win) */
//记录该连接曾经收到的最大有效ack值
	u_int32_t	td_maxack;	/* max of ack */
//通告窗口扩展因子
	u_int8_t	td_scale;	/* window scale factor */
	u_int8_t	flags;		/* per direction options */
};

struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];	/* connection parameters per direction */
	u_int8_t	state;		/* state of the connection (enum tcp_conntrack) */
	/* For detecting stale connections */
	u_int8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */
	u_int8_t	retrans;	/* Number of retransmitted packets */
	u_int8_t	last_index;	/* Index of the last packet */
	u_int32_t	last_seq;	/* Last sequence number seen in dir */
	u_int32_t	last_ack;	/* Last sequence number seen in opposite dir */
	u_int32_t	last_end;	/* Last seq + len */
	u_int16_t	last_win;	/* Last window advertisement seen in dir */
	/* For SYN packets while we may be out-of-sync */
	u_int8_t	last_wscale;	/* Last window scaling factor seen */
	u_int8_t	last_flags;	/* Last flags set */
};

#endif /* _NF_CONNTRACK_TCP_H */
