package common

import (
	"fmt"

	"XrayHelper/main/log"

	"github.com/coreos/go-iptables/iptables"
)

var protoLabels = map[iptables.Protocol]string{
	iptables.ProtocolIPv4: "ipv4",
	iptables.ProtocolIPv6: "ipv6",
}

var iptablesCandidates = map[iptables.Protocol][]string{
	iptables.ProtocolIPv4: {
		"", // autodiscover
		"iptables-legacy",
		"iptables-nft",
		"/system/bin/iptables",
		"/system/bin/iptables-legacy",
		"/system/bin/iptables-nft",
	},
	iptables.ProtocolIPv6: {
		"", // autodiscover
		"ip6tables-legacy",
		"ip6tables-nft",
		"/system/bin/ip6tables",
		"/system/bin/ip6tables-legacy",
		"/system/bin/ip6tables-nft",
	},
}

func initIPTables(proto iptables.Protocol) *iptables.IPTables {
	label := protoLabels[proto]
	for _, candidate := range iptablesCandidates[proto] {
		var (
			handler *iptables.IPTables
			err     error
		)
		if candidate == "" {
			handler, err = iptables.NewWithProtocol(proto)
			candidate = defaultCommand(proto)
		} else {
			handler, err = iptables.New(iptables.IPFamily(proto), iptables.Path(candidate))
		}
		if err != nil {
			log.HandleDebug(fmt.Sprintf("init %s iptables via %s failed: %v", label, candidate, err))
			continue
		}
		log.HandleDebug(fmt.Sprintf("init %s iptables via %s succeeded", label, candidate))
		return handler
	}
	log.HandleError(fmt.Sprintf("failed to init %s iptables", label))
	return nil
}

func defaultCommand(proto iptables.Protocol) string {
	if proto == iptables.ProtocolIPv6 {
		return "ip6tables"
	}
	return "iptables"
}

func EnsureChain(ipt *iptables.IPTables, table, chain string) error {
	if ipt == nil {
		return fmt.Errorf("iptables instance is nil")
	}
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		return fmt.Errorf("check chain %s in table %s: %w", chain, table, err)
	}
	if !exists {
		if err := ipt.NewChain(table, chain); err != nil {
			return fmt.Errorf("create chain %s in table %s: %w", chain, table, err)
		}
	}
	if err := ipt.ClearChain(table, chain); err != nil {
		return fmt.Errorf("clear chain %s in table %s: %w", chain, table, err)
	}
	return nil
}

func EnsureAppend(ipt *iptables.IPTables, table, chain string, rulespec ...string) error {
	if ipt == nil {
		return fmt.Errorf("iptables instance is nil")
	}
	if err := ipt.DeleteIfExists(table, chain, rulespec...); err != nil {
		return fmt.Errorf("cleanup existing rule in %s/%s: %w", table, chain, err)
	}
	if err := ipt.Append(table, chain, rulespec...); err != nil {
		return fmt.Errorf("append rule to %s/%s: %w", table, chain, err)
	}
	return nil
}

func EnsureInsert(ipt *iptables.IPTables, table, chain string, pos int, rulespec ...string) error {
	if ipt == nil {
		return fmt.Errorf("iptables instance is nil")
	}
	if err := ipt.DeleteIfExists(table, chain, rulespec...); err != nil {
		return fmt.Errorf("cleanup existing rule in %s/%s: %w", table, chain, err)
	}
	if err := ipt.Insert(table, chain, pos, rulespec...); err != nil {
		return fmt.Errorf("insert rule to %s/%s: %w", table, chain, err)
	}
	return nil
}
