package tproxy

import (
	"XrayHelper/main/builds"
	"XrayHelper/main/common"
	e "XrayHelper/main/errors"
	"XrayHelper/main/log"
	"XrayHelper/main/proxies/tools"
	"bytes"
	"strconv"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

const tagTproxy = "tproxy"

type Tproxy struct{}

func (this *Tproxy) Enable() error {
	if err := addRoute(false); err != nil {
		this.Disable()
		return err
	}
	if err := createProxyPreroutingChain(false); err != nil {
		this.Disable()
		return err
	}
	if err := createProxyOutputChain(false); err != nil {
		this.Disable()
		return err
	}
	if builds.Config.Proxy.EnableIPv6 {
		if err := addRoute(true); err != nil {
			this.Disable()
			return err
		}
		if err := createProxyPreroutingChain(true); err != nil {
			this.Disable()
			return err
		}
		if err := createProxyOutputChain(true); err != nil {
			this.Disable()
			return err
		}
	}
		if builds.Config.Proxy.BlockQuic {
		if err := blockQuic(false); err != nil {
			this.Disable()
			return err
		}
	}
	// handleDns, some core not support sniffing(eg: clash), need redirect dns request to local dns port
	switch builds.Config.XrayHelper.CoreType {
	case "mihomo":
		if err := tools.RedirectDNS(builds.Config.Clash.DNSPort); err != nil {
			this.Disable()
			return err
		}
	case "hysteria2":
		// hysteria2 don't have dns module, if enable AdgHome, as upstream dns resolver
		if builds.Config.AdgHome.Enable {
			if err := tools.RedirectDNS(builds.Config.AdgHome.DNSPort); err != nil {
				this.Disable()
				return err
			}
		}
	default:
		if !builds.Config.Proxy.EnableIPv6 {
			if err := tools.DisableIPV6DNS(); err != nil {
				this.Disable()
				return err
			}
		}
	}
	return nil
}
func (this *Tproxy) Disable() {
	deleteRoute(false)
	cleanIptablesChain(false)
		unblockQuic(false)
	//always clean ipv6 rules
	deleteRoute(true)
	cleanIptablesChain(true)
		unblockQuic(true)
	//always clean dns rules
	tools.EnableIPV6DNS()
	tools.CleanRedirectDNS(builds.Config.Clash.DNSPort)
	tools.CleanRedirectDNS(builds.Config.AdgHome.DNSPort)
}

// addRoute Add ip route to proxy
func addRoute(ipv6 bool) error {
	var errMsg bytes.Buffer
	if !ipv6 {
		common.NewExternal(0, nil, &errMsg, "ip", "rule", "add", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			return e.New("add ip rule failed, ", errMsg.String()).WithPrefix(tagTproxy)
		}
		errMsg.Reset()
		common.NewExternal(0, nil, &errMsg, "ip", "route", "add", "local", "default", "dev", "lo", "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			return e.New("add ip route failed, ", errMsg.String()).WithPrefix(tagTproxy)
		}
	} else {
		if !common.UseDummy {
			common.NewExternal(0, nil, &errMsg, "ip", "-6", "rule", "add", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
			if errMsg.Len() > 0 {
				return e.New("add ip rule failed, ", errMsg.String()).WithPrefix(tagTproxy)
			}
			errMsg.Reset()
			common.NewExternal(0, nil, &errMsg, "ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", common.TproxyTableId).Run()
			if errMsg.Len() > 0 {
				return e.New("add ip route failed, ", errMsg.String()).WithPrefix(tagTproxy)
			}
		} else {
			if err := enableDummy(); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteRoute Delete ip route to proxy
func deleteRoute(ipv6 bool) {
	var errMsg bytes.Buffer
	if !ipv6 {
		common.NewExternal(0, nil, &errMsg, "ip", "rule", "del", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip rule: " + errMsg.String())
		}
		errMsg.Reset()
		common.NewExternal(0, nil, &errMsg, "ip", "route", "flush", "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip route: " + errMsg.String())
		}
	} else {
		disableDummy()
		common.NewExternal(0, nil, &errMsg, "ip", "-6", "rule", "del", "fwmark", common.TproxyMarkId, "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip rule: " + errMsg.String())
		}
		errMsg.Reset()
		common.NewExternal(0, nil, &errMsg, "ip", "-6", "route", "flush", "table", common.TproxyTableId).Run()
		if errMsg.Len() > 0 {
			log.HandleDebug("delete ip route: " + errMsg.String())
		}
	}
}

// createProxyChain Create PROXY chain for local applications
func createProxyOutputChain(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}
	if currentIpt == nil {
		return e.New("get iptables failed").WithPrefix(tagTproxy)
	}
	chain := iptables.ChainTypeUserDefined
	chain.SetName("PROXY_OUTPUT")
	if err := currentIpt.Table(iptables.TableTypeMangle).NewChain("PROXY_OUTPUT"); err != nil {
		return e.New("create "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}

	// 1. conntrack optimization
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchConnTrack(iptables.WithMatchConnTrackDirection(iptables.REPLY)).TargetAccept().Append(); err != nil {
		return e.New("apply conntrack optimization on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}

	// 2. bypass addrtype LOCAL
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchAddrType(iptables.WithMatchAddrTypeDstType(false, iptables.LOCAL)).MatchProtocol(true, network.ProtocolUDP).TargetAccept().Append(); err != nil {
		return e.New("bypass addrtype LOCAL (TCP) on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchAddrType(iptables.WithMatchAddrTypeDstType(false, iptables.LOCAL)).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(true, 53)).TargetAccept().Append(); err != nil {
		return e.New("bypass addrtype LOCAL (UDP !53) on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}

	// bypass dummy
	if currentProto == "ipv6" && common.UseDummy {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOutInterface(false, common.DummyDevice).TargetReturn().Append(); err != nil {
			return e.New("ignore dummy interface "+common.DummyDevice+" on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// bypass ignore list
	for _, ignore := range builds.Config.Proxy.IgnoreList {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOutInterface(false, ignore).TargetReturn().Append(); err != nil {
			return e.New("apply ignore interface "+ignore+" on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// bypass intraNet list
	if currentProto == "ipv4" {
		for _, intraIp := range common.IntraNet {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp+" on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
			}
		}
	} else {
		for _, intraIp6 := range common.IntraNet6 {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp6).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp6+" on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// bypass Core itself
	coreGid, _ := strconv.Atoi(common.CoreGid)
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOwner(iptables.WithMatchOwnerGid(false, coreGid)).TargetReturn().Append(); err != nil {
		return e.New("bypass core gid on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}
	// start processing proxy rules
	// if PkgList has no package, should proxy everything
	if len(builds.Config.Proxy.PkgList) == 0 {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" tcp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	} else if builds.Config.Proxy.Mode == "blacklist" {
		// bypass PkgList
		for _, pkg := range builds.Config.Proxy.PkgList {
			uidSlice := tools.GetUid(pkg)
			for _, uid := range uidSlice {
				uidInt, _ := strconv.Atoi(uid)
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOwner(iptables.WithMatchOwnerUid(false, uidInt)).TargetReturn().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
					return e.New("bypass package "+pkg+" on "+currentProto+" mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		// allow others
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" tcp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	} else if builds.Config.Proxy.Mode == "whitelist" {
		// allow PkgList
		for _, pkg := range builds.Config.Proxy.PkgList {
			uidSlice := tools.GetUid(pkg)
			for _, uid := range uidSlice {
				uidInt, _ := strconv.Atoi(uid)
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchOwner(iptables.WithMatchOwnerUid(false, uidInt)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
					return e.New("create package "+pkg+" proxy on "+currentProto+" tcp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
				}
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerUid(false, uidInt)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
					return e.New("create package "+pkg+" proxy on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		// allow root user(eg: magisk, ksud, netd...)
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchOwner(iptables.WithMatchOwnerUid(false, 0)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create root user proxy on "+currentProto+" tcp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerUid(false, 0)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create root user proxy on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
		// allow dns_tether user(eg: dnsmasq...)
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchOwner(iptables.WithMatchOwnerUid(false, 1052)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create dns_tether user proxy on "+currentProto+" tcp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerUid(false, 1052)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create dns_tether user proxy on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		return e.New("invalid proxy mode " + builds.Config.Proxy.Mode).WithPrefix(tagTproxy)
	}
	// allow IntraList
	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, intra).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, intra).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// mark all dns request (except mihomo/hysteria2)
	if builds.Config.XrayHelper.CoreType != "mihomo" && builds.Config.XrayHelper.CoreType != "hysteria2" {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerGid(true, coreGid)).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("mark all dns request on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReturn().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("bypass all dns request on "+currentProto+" udp mangle chain PROXY_OUTPUT failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// apply rules to OUTPUT
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("PROXY_OUTPUT").Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("apply mangle chain PROXY_OUTPUT to OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}
	return nil
}

// createMangleChain Create XRAY chain for AP interface
func createProxyPreroutingChain(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}
	if currentIpt == nil {
		return e.New("get iptables failed").WithPrefix(tagTproxy)
	}
	chain := iptables.ChainTypeUserDefined
	chain.SetName("PROXY_PREROUTING")
	if err := currentIpt.Table(iptables.TableTypeMangle).NewChain("PROXY_PREROUTING"); err != nil {
		return e.New("create "+currentProto+" mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}

	// 0. create DIVERT chain
	chainDivert := iptables.ChainTypeUserDefined
	chainDivert.SetName("DIVERT")
	if err := currentIpt.Table(iptables.TableTypeMangle).NewChain("DIVERT"); err != nil {
		return e.New("create "+currentProto+" mangle chain DIVERT failed, ", err).WithPrefix(tagTproxy)
	}
	tproxyMark, _ := strconv.Atoi(common.TproxyMarkId)
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chainDivert).TargetMark(iptables.WithTargetMarkSetX(tproxyMark, tproxyMark)).Append(); err != nil {
		return e.New("mark DIVERT traffic on "+currentProto+" mangle chain DIVERT failed, ", err).WithPrefix(tagTproxy)
	}
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chainDivert).TargetAccept().Append(); err != nil {
		return e.New("accept DIVERT traffic on "+currentProto+" mangle chain DIVERT failed, ", err).WithPrefix(tagTproxy)
	}

	// 1. conntrack optimization
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchConnTrack(iptables.WithMatchConnTrackDirection(iptables.REPLY)).TargetAccept().Append(); err != nil {
		return e.New("apply conntrack optimization on "+currentProto+" mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}

	// 2. socket optimization
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchSocket(iptables.WithMatchSocketTransparent()).TargetJumpChain("DIVERT").Append(); err != nil {
		return e.New("apply socket optimization on "+currentProto+" mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}

	// bypass intraNet list
	if currentProto == "ipv4" {
		for _, intraIp := range common.IntraNet {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp+" on "+currentProto+" mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
			}
		}
	} else {
		for _, intraIp6 := range common.IntraNet6 {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp6).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp6+" on "+currentProto+" mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	tproxyPort, _ := strconv.Atoi(builds.Config.Proxy.TproxyPort)
	// allow IntraList
	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, intra).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, intra).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// mark all traffic
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
		return e.New("create all traffic proxy on "+currentProto+" tcp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
		return e.New("create all traffic proxy on "+currentProto+" udp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}
	// trans ApList to chain XRAY
	for _, ap := range builds.Config.Proxy.ApList {
		// allow ApList to IntraList
		for _, intra := range builds.Config.Proxy.IntraList {
			if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchInInterface(false, ap).MatchDestination(false, intra).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
					return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
				}
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchInInterface(false, ap).MatchDestination(false, intra).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
					return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchInInterface(false, ap).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create ap interface "+ap+" proxy on "+currentProto+" tcp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchInInterface(false, ap).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create ap interface "+ap+" proxy on "+currentProto+" udp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// mark all dns request(except mihomo/hysteria2)
	if builds.Config.XrayHelper.CoreType != "mihomo" && builds.Config.XrayHelper.CoreType != "hysteria2" {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("mark all dns request on "+currentProto+" udp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReturn().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("bypass all dns request on "+currentProto+" udp mangle chain PROXY_PREROUTING failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// apply rules to PREROUTING
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).TargetJumpChain("PROXY_PREROUTING").Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("apply mangle chain PROXY_PREROUTING to PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}
	return nil
}


func blockQuic(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}
	if currentIpt == nil {
		return e.New("get iptables failed").WithPrefix(tagTproxy)
	}

	chain := iptables.ChainTypeUserDefined
	chain.SetName("BLOCK_QUIC")
	_ = currentIpt.Table(iptables.TableTypeFilter).NewChain("BLOCK_QUIC")

	if err := currentIpt.Table(iptables.TableTypeFilter).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 443)).TargetReject().Append(); err != nil {
		return e.New("block quic on "+currentProto+" filter chain BLOCK_QUIC failed, ", err).WithPrefix(tagTproxy)
	}

	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeINPUT).TargetJumpChain("BLOCK_QUIC").Insert(iptables.WithCommandInsertRuleNumber(1))
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).TargetJumpChain("BLOCK_QUIC").Insert(iptables.WithCommandInsertRuleNumber(1))
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("BLOCK_QUIC").Insert(iptables.WithCommandInsertRuleNumber(1))

	return nil
}

func unblockQuic(ipv6 bool) {
	currentIpt := common.Ipt
	if ipv6 {
		currentIpt = common.Ipt6
	}
	if currentIpt == nil {
		return
	}
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeINPUT).TargetJumpChain("BLOCK_QUIC").Delete()
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).TargetJumpChain("BLOCK_QUIC").Delete()
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("BLOCK_QUIC").Delete()

	chain := iptables.ChainTypeUserDefined
	chain.SetName("BLOCK_QUIC")
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(chain).Flush()
	_ = currentIpt.Table(iptables.TableTypeFilter).Chain(chain).DeleteChain()
}

func cleanIptablesChain(ipv6 bool) {
	currentIpt := common.Ipt
	if ipv6 {
		currentIpt = common.Ipt6
	}
	if currentIpt == nil {
		return
	}
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("PROXY_OUTPUT").Delete()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).TargetJumpChain("PROXY_PREROUTING").Delete()
	
	// Delete PROXY_OUTPUT
	chainProxyOutput := iptables.ChainTypeUserDefined
	chainProxyOutput.SetName("PROXY_OUTPUT")
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainProxyOutput).Flush()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainProxyOutput).DeleteChain()

	// Delete PROXY_PREROUTING
	chainProxyPrerouting := iptables.ChainTypeUserDefined
	chainProxyPrerouting.SetName("PROXY_PREROUTING")
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainProxyPrerouting).Flush()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainProxyPrerouting).DeleteChain()

	// Delete DIVERT
	chainDivert := iptables.ChainTypeUserDefined
	chainDivert.SetName("DIVERT")
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainDivert).Flush()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainDivert).DeleteChain()

}


func setupBypassIpChain(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}

	chain := iptables.ChainTypeUserDefined
	chain.SetName("BYPASS_IP")
	_ = currentIpt.Table(iptables.TableTypeMangle).NewChain("BYPASS_IP")

	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchAddrType(iptables.WithMatchAddrTypeDstType(false, iptables.LOCAL)).MatchProtocol(true, network.ProtocolUDP).TargetAccept().Append(); err != nil {
		return err
	}
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchAddrType(iptables.WithMatchAddrTypeDstType(false, iptables.LOCAL)).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(true, 53)).TargetAccept().Append(); err != nil {
		return err
	}

	for _, ignore := range builds.Config.Proxy.IgnoreList {
		if (currentProto == "ipv4" && !common.IsIPv6(ignore)) || (currentProto == "ipv6" && common.IsIPv6(ignore)) {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, ignore).TargetAccept().Append(); err != nil {
				return err
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, ignore).TargetAccept().Append(); err != nil {
				return err
			}
		}
	}
	return nil
}

func setupProxyIpChain(ipv6 bool) error {
	currentIpt := common.Ipt
	currentProto := "ipv4"
	if ipv6 {
		currentIpt = common.Ipt6
		currentProto = "ipv6"
	}
	
	tproxyPort, _ := strconv.Atoi(builds.Config.Proxy.TproxyPort)
	tproxyMark, _ := strconv.Atoi(common.TproxyMarkId)

	chainOut := iptables.ChainTypeUserDefined
	chainOut.SetName("PROXY_IP_OUT")
	_ = currentIpt.Table(iptables.TableTypeMangle).NewChain("PROXY_IP_OUT")

	chainPre := iptables.ChainTypeUserDefined
	chainPre.SetName("PROXY_IP_PRE")
	_ = currentIpt.Table(iptables.TableTypeMangle).NewChain("PROXY_IP_PRE")

	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chainOut).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, intra).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
				return err
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chainOut).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, intra).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
				return err
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chainPre).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, intra).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(tproxyMark, tproxyMark)).Append(); err != nil {
				return err
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chainPre).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, intra).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(tproxyMark, tproxyMark)).Append(); err != nil {
				return err
			}
		}
	}
	return nil
}

func setupProxyInterfaceChain(ipv6 bool) error {
	currentIpt := common.Ipt
	if ipv6 {
		currentIpt = common.Ipt6
	}
	chain := iptables.ChainTypeUserDefined
	chain.SetName("PROXY_INTERFACE")
	_ = currentIpt.Table(iptables.TableTypeMangle).NewChain("PROXY_INTERFACE")

	for _, ap := range builds.Config.Proxy.ApList {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchInInterface(false, ap).TargetReturn().Append(); err != nil {
			return err
		}
	}
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).TargetAccept().Append(); err != nil {
		return err
	}
	return nil
}
