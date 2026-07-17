package tools

import (
	"XrayHelper/main/builds"
	"XrayHelper/main/common"
	e "XrayHelper/main/errors"
	"XrayHelper/main/log"
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

const (
	tagTools        = "tools"
	packageListPath = "/data/system/packages.list"
)

var packageMap = make(map[string]string)

// loadPackage load and parse Android package with uid list into a map
func loadPackage() {
	if len(packageMap) > 0 {
		return
	}
	packageListFile, err := os.Open(packageListPath)
	if err != nil {
		log.HandleDebug("load package failed, " + err.Error())
		return
	}
	defer packageListFile.Close()
	packageScanner := bufio.NewScanner(packageListFile)
	packageScanner.Split(bufio.ScanLines)
	for packageScanner.Scan() {
		packageInfo := strings.Fields(packageScanner.Text())
		if len(packageInfo) >= 2 {
			packageMap[packageInfo[0]] = packageInfo[1]
		}
	}
	log.HandleDebug(packageMap)
}

func GetUid(pkgInfo string) []string {
	loadPackage()
	var (
		userId    int
		pkgUserId []string
	)
	info := strings.Split(pkgInfo, ":")
	if len(info) == 2 {
		userId, _ = strconv.Atoi(info[1])
	}
	for pkgStr, pkgIdStr := range packageMap {
		if common.WildcardMatch(pkgStr, info[0]) {
			pkgId, _ := strconv.Atoi(pkgIdStr)
			pkgUserIdStr := strconv.Itoa(userId*100000 + pkgId)
			pkgUserId = append(pkgUserId, pkgUserIdStr)
		}
	}
	return pkgUserId
}

func DisableIPV6DNS() error {
	if err := common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeOUTPUT).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReject().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("disable dns request on ipv6 failed, ", err).WithPrefix(tagTools)
	}
	return nil
}

func EnableIPV6DNS() {
	_ = common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeOUTPUT).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReject().Delete()
}

func RedirectDNS(port string) error {
	portInt, _ := strconv.Atoi(port)
	coreGid, _ := strconv.Atoi(common.CoreGid)
	
	chain := iptables.ChainTypeUserDefined
	chain.SetName("NAT_DNS_HIJACK")
	_ = common.Ipt.Table(iptables.TableTypeNat).NewChain("NAT_DNS_HIJACK")

	// redirect UDP and TCP 53 to local port
	if err := common.Ipt.Table(iptables.TableTypeNat).Chain(chain).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetRedirect(iptables.WithTargetRedirectToPort(portInt)).Append(); err != nil {
		return e.New("redirect dns request udp failed, ", err).WithPrefix(tagTools)
	}
	if err := common.Ipt.Table(iptables.TableTypeNat).Chain(chain).MatchProtocol(false, network.ProtocolTCP).MatchTCP(iptables.WithMatchTCPDstPort(false, 53)).TargetRedirect(iptables.WithTargetRedirectToPort(portInt)).Append(); err != nil {
		return e.New("redirect dns request tcp failed, ", err).WithPrefix(tagTools)
	}

	// hook to OUTPUT
	if err := common.Ipt.Table(iptables.TableTypeNat).Chain(iptables.ChainTypeOUTPUT).MatchOwner(iptables.WithMatchOwnerGid(true, coreGid)).TargetJumpChain("NAT_DNS_HIJACK").Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("jump NAT_DNS_HIJACK from OUTPUT failed, ", err).WithPrefix(tagTools)
	}

	// hook to PREROUTING for tethering interfaces
	for _, ap := range builds.Config.Proxy.ApList {
		if err := common.Ipt.Table(iptables.TableTypeNat).Chain(iptables.ChainTypePREROUTING).MatchInInterface(false, ap).TargetJumpChain("NAT_DNS_HIJACK").Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
			return e.New("jump NAT_DNS_HIJACK from PREROUTING for "+ap+" failed, ", err).WithPrefix(tagTools)
		}
	}

	if err := DisableIPV6DNS(); err != nil {
		return err
	}
	return nil
}

func CleanRedirectDNS(port string) {
	coreGid, _ := strconv.Atoi(common.CoreGid)
	_ = common.Ipt.Table(iptables.TableTypeNat).Chain(iptables.ChainTypeOUTPUT).MatchOwner(iptables.WithMatchOwnerGid(true, coreGid)).TargetJumpChain("NAT_DNS_HIJACK").Delete()
	
	for _, ap := range builds.Config.Proxy.ApList {
		_ = common.Ipt.Table(iptables.TableTypeNat).Chain(iptables.ChainTypePREROUTING).MatchInInterface(false, ap).TargetJumpChain("NAT_DNS_HIJACK").Delete()
	}

	chain := iptables.ChainTypeUserDefined
	chain.SetName("NAT_DNS_HIJACK")
	_ = common.Ipt.Table(iptables.TableTypeNat).Chain(chain).Flush()
	_ = common.Ipt.Table(iptables.TableTypeNat).Chain(chain).DeleteChain()

	EnableIPV6DNS()
}

func EnableForward(device string) error {
	if err := common.Ipt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchInInterface(false, device).TargetAccept().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("enable ipv4 forward for "+device+" incoming failed, ", err).WithPrefix(tagTools)
	}
	if err := common.Ipt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchOutInterface(false, device).TargetAccept().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("enable ipv4 forward for "+device+" outgoing failed, ", err).WithPrefix(tagTools)
	}
	if err := common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchInInterface(false, device).TargetAccept().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("enable ipv6 forward for "+device+" incoming failed, ", err).WithPrefix(tagTools)
	}
	if err := common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchOutInterface(false, device).TargetAccept().Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("enable ipv6 forward for "+device+" outgoing failed, ", err).WithPrefix(tagTools)
	}
	return nil
}

func DisableForward(device string) {
	_ = common.Ipt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchInInterface(false, device).TargetAccept().Delete()
	_ = common.Ipt.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchOutInterface(false, device).TargetAccept().Delete()
	_ = common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchInInterface(false, device).TargetAccept().Delete()
	_ = common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeFORWARD).MatchOutInterface(false, device).TargetAccept().Delete()
}
