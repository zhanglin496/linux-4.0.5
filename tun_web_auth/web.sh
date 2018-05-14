#!/bin/sh

AUTH_CHAIN=WEB_AUTH_CHAIN
case $1 in
	add)
		iptables -t mangle -N $AUTH_CHAIN
		iptables -t mangle -F $AUTH_CHAIN
		iptables -t mangle -A $AUTH_CHAIN -p tcp --dport 80 -j CONNMARK --restore-mark
		iptables -t mangle -A $AUTH_CHAIN -p tcp --dport 80 -m mark --mark 0x30 -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -m state --state ESTABLISHED -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -p udp --dport 53 -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -p udp --dport 67 -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -m set --match-set web_auth src -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -m set --match-set web_auth2 dst -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -p tcp --dport 80 -j MARK --set-mark 0x30
		iptables -t mangle -A $AUTH_CHAIN -p tcp --dport 80 -m mark --mark 0x30 -j CONNMARK --save-mark
		iptables -t mangle -A $AUTH_CHAIN -p tcp --dport 80 -m mark --mark 0x30 -j RETURN
		iptables -t mangle -A $AUTH_CHAIN -j DROP
		iptables -t mangle -A PREROUTING -j $AUTH_CHAIN
		./auth-box &
		ifconfig tap0 up
		ip addr add 192.168.3.1/24 dev tap0
		ipset add web_auth2 192.168.1.1/24
		ipset add web_auth2 127.0.0.0/8
		ip ro add default dev tap0 table 110
		ip ru add fwmark 0x30 lookup 110
	;;
	del)
		killall -9 auth-box
		iptables -t mangle -D PREROUTING -j $AUTH_CHAIN
		iptables -t mangle -F $AUTH_CHAIN
		iptables -t mangle -X $AUTH_CHAIN
		ip ro del default dev tap0 table 110
		ip ru del fwmark 0x30 lookup 110
	;;
esac


