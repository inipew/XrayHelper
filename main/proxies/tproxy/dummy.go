package tproxy

import (
	"XrayHelper/main/builds"
	"XrayHelper/main/common"
	e "XrayHelper/main/errors"
	"XrayHelper/main/log"
	"bytes"
	"net"
	"strconv"

	"github.com/singchia/go-xtables/iptables"
	"github.com/singchia/go-xtables/pkg/network"
)

const tagDummy = "dummy"

func createDummyDevice() error {
	var errMsg bytes.Buffer
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "link", "add", common.DummyDevice, "type", "dummy").Run()
	if errMsg.Len() > 0 {
		return e.New("add dummy device failed, ", errMsg.String()).WithPrefix(tagDummy)
	}
	errMsg.Reset()
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "addr", "add", common.DummyIp, "dev", common.DummyDevice).Run()
	if errMsg.Len() > 0 {
		return e.New("add dummy ip failed, ", errMsg.String()).WithPrefix(tagDummy)
	}
	errMsg.Reset()
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "link", "set", common.DummyDevice, "up").Run()
	if errMsg.Len() > 0 {
		return e.New("set dummy up failed, ", errMsg.String()).WithPrefix(tagDummy)
	}
	return nil
}

func removeDummyDevice() {
	var errMsg bytes.Buffer
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "link", "set", common.DummyDevice, "down").Run()
	if errMsg.Len() > 0 {
		log.HandleDebug("set dummy down failed: " + errMsg.String())
	}
	errMsg.Reset()
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "link", "del", common.DummyDevice, "type", "dummy").Run()
	if errMsg.Len() > 0 {
		log.HandleDebug("delete dummy device: " + errMsg.String())
	}
}

func addDummyRoute() error {
	var errMsg bytes.Buffer
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "rule", "add", "not", "from", "all", "fwmark", common.DummyMarkId, "table", common.DummyTableId).Run()
	if errMsg.Len() > 0 {
		return e.New("add dummy rule failed, ", errMsg.String()).WithPrefix(tagDummy)
	}
	errMsg.Reset()
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "route", "add", "local", "default", "dev", common.DummyDevice, "table", common.DummyTableId).Run()
	if errMsg.Len() > 0 {
		return e.New("add dummy route failed, ", errMsg.String()).WithPrefix(tagDummy)
	}
	return nil
}

func deleteDummyRoute() {
	var errMsg bytes.Buffer
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "rule", "del", "not", "from", "all", "fwmark", common.DummyMarkId, "table", common.DummyTableId).Run()
	if errMsg.Len() > 0 {
		log.HandleDebug("delete dummy rule: " + errMsg.String())
	}
	errMsg.Reset()
	common.NewExternal(0, nil, &errMsg, "ip", "-6", "route", "del", "local", "default", "dev", common.DummyDevice, "table", common.DummyTableId).Run()
	if errMsg.Len() > 0 {
		log.HandleDebug("delete dummy route: " + errMsg.String())
	}
}

func createDummyOutputChain() error {
	chain := iptables.ChainTypeUserDefined
	chain.SetName("DUMMY")
	if err := common.Ipt6.Table(iptables.TableTypeMangle).NewChain("DUMMY"); err != nil {
		return e.New("create ipv6 mangle chain DUMMY failed, ", err).WithPrefix(tagDummy)
	}
	if err := common.Ipt6.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).MatchInInterface(false, common.DummyDevice).TargetMark(iptables.WithTargetMarkSetX(0x2000000, 0x2000000)).Append(); err != nil {
		return e.New("create dummy prerouting mark on ipv6 mangle chain failed, ", err).WithPrefix(tagTproxy)
	}
	if err := common.Ipt6.Table(iptables.TableTypeMangle).Chain(chain).MatchProtocol(false, network.ProtocolTCP).TargetMark(iptables.WithTargetMarkSetX(0x2000000, 0x2000000)).Append(); err != nil {
		return e.New("set mark on udp mangle chain DUMMY failed, ", err).WithPrefix(tagDummy)
	}
	if err := common.Ipt6.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("DUMMY").Append(); err != nil {
		return e.New("apply ipv6 mangle chain DUMMY on OUTPUT failed, ", err).WithPrefix(tagDummy)
	}
	return nil
}

func createDummyPreroutingChain() error {
	chain := iptables.ChainTypeUserDefined
	chain.SetName("XD")
	if err := common.Ipt6.Table(iptables.TableTypeMangle).NewChain("XD"); err != nil {
		return e.New("create ipv6 mangle chain XD failed, ", err).WithPrefix(tagDummy)
	}
	tproxyPort, _ := strconv.Atoi(builds.Config.Proxy.TproxyPort)
	if err := common.Ipt6.Table(iptables.TableTypeMangle).Chain(chain).MatchInInterface(false, common.DummyDevice).MatchProtocol(false, network.ProtocolTCP).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyOnIP(net.ParseIP("::")), iptables.WithTargetTProxyMark(0x2000000, 0x2000000)).Append(); err != nil {
		return e.New("create dummy tproxy on ipv6 mangle chain failed, ", err).WithPrefix(tagTproxy)
	}
	if err := common.Ipt6.Table(iptables.TableTypeMangle).Chain(chain).MatchInInterface(false, common.DummyDevice).MatchProtocol(false, network.ProtocolUDP).TargetTProxy(iptables.WithTargetTProxyOnPort(tproxyPort), iptables.WithTargetTProxyOnIP(net.ParseIP("::")), iptables.WithTargetTProxyMark(0x2000000, 0x2000000)).Append(); err != nil {
		return e.New("set mark on udp mangle chain XD failed, ", err).WithPrefix(tagDummy)
	}
	if err := common.Ipt6.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).TargetJumpChain("XD").Append(); err != nil {
		return e.New("apply ipv6 mangle chain XD on PREROUTING failed, ", err).WithPrefix(tagDummy)
	}
	return nil
}

func cleanDummyChain() {
	chainDUMMY := iptables.ChainTypeUserDefined
	chainDUMMY.SetName("DUMMY")
	_ = common.Ipt6.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypeOUTPUT).TargetJumpChain("DUMMY").Delete()
	_ = common.Ipt6.Table(iptables.TableTypeMangle).Chain(iptables.ChainTypePREROUTING).TargetJumpChain("XD").Delete()
	chainXD := iptables.ChainTypeUserDefined
	chainXD.SetName("XD")
	_ = common.Ipt6.Table(iptables.TableTypeMangle).Chain(chainDUMMY).Flush()
	_ = common.Ipt6.Table(iptables.TableTypeMangle).Chain(chainDUMMY).DeleteChain()
	_ = common.Ipt6.Table(iptables.TableTypeMangle).Chain(chainXD).Flush()
	_ = common.Ipt6.Table(iptables.TableTypeMangle).Chain(chainXD).DeleteChain()
}

func enableDummy() error {
	if err := createDummyDevice(); err != nil {
		return err
	}
	if err := addDummyRoute(); err != nil {
		return err
	}
	if err := createDummyPreroutingChain(); err != nil {
		return err
	}
	if err := createDummyOutputChain(); err != nil {
		return err
	}
	return nil
}

func disableDummy() {
	cleanDummyChain()
	deleteDummyRoute()
	removeDummyDevice()
}
