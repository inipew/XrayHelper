package common

import "github.com/coreos/go-iptables/iptables"

const (
	CoreGid             = "3005"
	TproxyTableId       = "160"
	TproxyMarkId        = "0x1000000/0x1000000"
	DummyDevice         = "xdummy"
	DummyIp             = "fd01:5ca1:ab1e:8d97:497f:8b48:b9aa:85cd/128"
	DummyMarkId         = "0x2000000/0x2000000"
	DummyTableId        = "164"
	Tun2socksIPv4       = "10.10.12.1"
	Tun2socksIPv6       = "fd02:5ca1:ab1e:8d97:497f:8b48:b9aa:85cd"
	Tun2socksMTU        = 8500
	Tun2socksMultiQueue = false
	Tun2socksUdpMode    = "udp"
	TunTableId          = "168"
	TunMarkId           = "0x4000000/0x4000000"
)

var (
	Ipt, _   = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	Ipt6, _  = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	IntraNet = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"}
	IntraNet6 = []string{"::/128", "::1/128", "::ffff:0:0/96", "100::/64", "64:ff9b::/96", "2001::/32",
		"2001:10::/28", "2001:20::/28", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"}
	ExternalIPv6 []string
)

func init() {
	if ext, err := getExternalIPv6Addr(); err == nil {
		ExternalIPv6 = append(ExternalIPv6, ext...)
	}
}
