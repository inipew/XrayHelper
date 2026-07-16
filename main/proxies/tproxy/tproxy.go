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
	if err := createMangleChain(false); err != nil {
		this.Disable()
		return err
	}
	if err := createProxyChain(false); err != nil {
		this.Disable()
		return err
	}
	if builds.Config.Proxy.EnableIPv6 {
		if err := addRoute(true); err != nil {
			this.Disable()
			return err
		}
		if err := createMangleChain(true); err != nil {
			this.Disable()
			return err
		}
		if err := createProxyChain(true); err != nil {
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
	//always clean ipv6 rules
	deleteRoute(true)
	cleanIptablesChain(true)
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
func createProxyChain(ipv6 bool) error {
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
	chain.SetName("PROXY")
	if err := currentIpt.Table(iptables.TableTypeMangle).NewChain("PROXY"); err != nil {
		return e.New("create "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
	}
	// bypass dummy
	if currentProto == "ipv6" && common.UseDummy {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOutInterface(false, common.DummyDevice).TargetReturn().Append(); err != nil {
			return e.New("ignore dummy interface "+common.DummyDevice+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// bypass ignore list
	for _, ignore := range builds.Config.Proxy.IgnoreList {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOutInterface(false, ignore).TargetReturn().Append(); err != nil {
			return e.New("apply ignore interface "+ignore+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// bypass intraNet list
	if currentProto == "ipv4" {
		for _, intraIp := range common.IntraNet {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	} else {
		for _, intraIp6 := range common.IntraNet6 {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp6).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp6+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// bypass Core itself
	coreGid, _ := strconv.Atoi(common.CoreGid)
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOwner(iptables.WithMatchOwnerGid(false, coreGid)).TargetReturn().Append(); err != nil {
		return e.New("bypass core gid on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
	}
	// start processing proxy rules
	// if PkgList has no package, should proxy everything
	if len(builds.Config.Proxy.PkgList) == 0 {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else if builds.Config.Proxy.Mode == "blacklist" {
		// bypass PkgList
		for _, pkg := range builds.Config.Proxy.PkgList {
			uidSlice := tools.GetUid(pkg)
			for _, uid := range uidSlice {
				uidInt, _ := strconv.Atoi(uid)
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchOwner(iptables.WithMatchOwnerUid(false, uidInt)).TargetReturn().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
					return e.New("bypass package "+pkg+" on "+currentProto+" mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		// allow others
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create local applications proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else if builds.Config.Proxy.Mode == "whitelist" {
		// allow PkgList
		for _, pkg := range builds.Config.Proxy.PkgList {
			uidSlice := tools.GetUid(pkg)
			for _, uid := range uidSlice {
				uidInt, _ := strconv.Atoi(uid)
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchOwner(iptables.WithMatchOwnerUid(false, uidInt)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
					return e.New("create package "+pkg+" proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
				}
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerUid(false, uidInt)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
					return e.New("create package "+pkg+" proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		// allow root user(eg: magisk, ksud, netd...)
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchOwner(iptables.WithMatchOwnerUid(false, 0)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create root user proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerUid(false, 0)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create root user proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		// allow dns_tether user(eg: dnsmasq...)
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchOwner(iptables.WithMatchOwnerUid(false, 1052)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create dns_tether user proxy on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerUid(false, 1052)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create dns_tether user proxy on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		return e.New("invalid proxy mode " + builds.Config.Proxy.Mode).WithPrefix(tagTproxy)
	}
	// allow IntraList
	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, intra).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, intra).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// mark all dns request (except mihomo/hysteria2)
	if builds.Config.XrayHelper.CoreType != "mihomo" && builds.Config.XrayHelper.CoreType != "hysteria2" {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerGid(true, coreGid)).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetMark(iptables.WithTargetMarkSetX(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("mark all dns request on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReturn().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("bypass all dns request on "+currentProto+" udp mangle chain PROXY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// apply rules to OUTPUT
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("PROXY").Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("apply mangle chain PROXY to OUTPUT failed, ", err).WithPrefix(tagTproxy)
	}
	return nil
}

// createMangleChain Create XRAY chain for AP interface
func createMangleChain(ipv6 bool) error {
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
	chain.SetName("XRAY")
	if err := currentIpt.Table(iptables.TableTypeMangle).NewChain("XRAY"); err != nil {
		return e.New("create "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
	}
	// bypass intraNet list
	if currentProto == "ipv4" {
		for _, intraIp := range common.IntraNet {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp+" on "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	} else {
		for _, intraIp6 := range common.IntraNet6 {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchDestination(false, intraIp6).TargetReturn().Append(); err != nil {
				return e.New("bypass intraNet "+intraIp6+" on "+currentProto+" mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	tproxyPort, _ := strconv.Atoi(builds.Config.Proxy.TproxyPort)
	// allow IntraList
	for _, intra := range builds.Config.Proxy.IntraList {
		if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchDestination(false, intra).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
			if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchDestination(false, intra).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
				return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
			}
		}
	}
	// mark all traffic
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
		return e.New("create all traffic proxy on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
	}
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchMark(false, 0x1000000, 0x1000000).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
		return e.New("create all traffic proxy on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
	}
	// trans ApList to chain XRAY
	for _, ap := range builds.Config.Proxy.ApList {
		// allow ApList to IntraList
		for _, intra := range builds.Config.Proxy.IntraList {
			if (currentProto == "ipv4" && !common.IsIPv6(intra)) || (currentProto == "ipv6" && common.IsIPv6(intra)) {
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchInInterface(false, ap).MatchDestination(false, intra).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
					return e.New("allow intra "+intra+" on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
				}
				if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchInInterface(false, ap).MatchDestination(false, intra).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
					return e.New("allow intra "+intra+" on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
				}
			}
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchInInterface(false, ap).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create ap interface "+ap+" proxy on "+currentProto+" tcp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchInInterface(false, ap).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Append(); err != nil {
			return e.New("create ap interface "+ap+" proxy on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// mark all dns request(except mihomo/hysteria2)
	if builds.Config.XrayHelper.CoreType != "mihomo" && builds.Config.XrayHelper.CoreType != "hysteria2" {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyMark(0x1000000, 0x1000000)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("mark all dns request on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
	} else {
		if err := currentIpt.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReturn().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("bypass all dns request on "+currentProto+" udp mangle chain XRAY failed, ", err).WithPrefix(tagTproxy)
		}
	}
	// apply rules to PREROUTING
	if err := currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).TargetJumpChain("XRAY").Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("apply mangle chain XRAY to PREROUTING failed, ", err).WithPrefix(tagTproxy)
	}
	return nil
}

func cleanIptablesChain(ipv6 bool) {
	currentIpt := common.Ipt
	if ipv6 {
		currentIpt = common.Ipt6
	}
	if currentIpt == nil {
		return
	}
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("PROXY").Delete()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).TargetJumpChain("XRAY").Delete()
	chainPROXY := iptables.ChainTypeUserDefined
	chainPROXY.SetName("PROXY")
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainPROXY).Flush()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainPROXY).DeleteChain()
	chainXRAY := iptables.ChainTypeUserDefined
	chainXRAY.SetName("XRAY")
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainXRAY).Flush()
	_ = currentIpt.Table(iptables.TableTypeMangle).Chain(chainXRAY).DeleteChain()
}
