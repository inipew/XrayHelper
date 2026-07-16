package tools

import (
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
	if err := common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeOUTPUT).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReject(iptables.WithTargetRejectType(iptables.RejectType(7))).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("disable dns request on ipv6 failed, ", err).WithPrefix(tagTools)
	}
	return nil
}

func EnableIPV6DNS() {
	_ = common.Ipt6.Table(iptables.TableTypeFilter).Chain(iptables.ChainTypeOUTPUT).MatchProtocol(false, network.ProtocolUDP).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetReject(iptables.WithTargetRejectType(iptables.RejectType(7))).Delete()
}

func RedirectDNS(port string) error {
	portInt, _ := strconv.Atoi(port)
	coreGid, _ := strconv.Atoi(common.CoreGid)
	if err := common.Ipt.Table(iptables.TableTypeNat).Chain(iptables.ChainTypeOUTPUT).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerGid(true, coreGid)).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetDNAT(iptables.WithTargetDNATToAddr(network.ParseIP("127.0.0.1"), portInt)).Insert(iptables.WithCommandInsertRuleNumber(1)); err != nil {
		return e.New("redirect dns request failed, ", err).WithPrefix(tagTools)
	}
	if err := DisableIPV6DNS(); err != nil {
		return err
	}
	return nil
}

func CleanRedirectDNS(port string) {
	portInt, _ := strconv.Atoi(port)
	coreGid, _ := strconv.Atoi(common.CoreGid)
	_ = common.Ipt.Table(iptables.TableTypeNat).Chain(iptables.ChainTypeOUTPUT).MatchProtocol(false, network.ProtocolUDP).MatchOwner(iptables.WithMatchOwnerGid(true, coreGid)).MatchUDP(iptables.WithMatchUDPDstPort(false, 53)).TargetDNAT(iptables.WithTargetDNATToAddr(network.ParseIP("127.0.0.1"), portInt)).Delete()
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
