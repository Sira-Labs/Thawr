package wg

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// routerNAT installs, for a userspace tunnel on Linux, the forward and
// nat chains a router needs; the input filter itself stays in
// userspace. Nothing is installed while the set carries no forward
// rule and no masquerade prefix, so plain clients never touch
// nftables.
type routerNAT struct {
	nft nftFilter
}

func (r *routerNAT) set(ctx context.Context, set FilterSet) error {
	if len(set.Forward) == 0 && len(set.Masquerade) == 0 {
		return r.nft.remove()
	}
	set.Rules, set.Visible = nil, nil
	set.Hook = HookInput
	return r.nft.SetFilter(ctx, FilterSet{Interface: set.Interface, Hook: HookInput, Local: set.Local, Forward: set.Forward, Masquerade: set.Masquerade, MasqueradeFrom: set.MasqueradeFrom, routerOnly: true})
}

func (r *routerNAT) remove() error { return r.nft.remove() }

// AllowForward lets packets that the hub forwards from iface back to
// iface pass every foreign forward chain whose policy is drop. Docker
// installs such a chain (`ip filter FORWARD`, policy DROP) on every
// host it runs on, which silently blocks phone-to-peer traffic through
// the hub. The rule is inserted at the top of each such chain, once,
// and the returned undo removes it again. Thawr's own table is never
// touched. Chains reports how many chains received the rule.
func AllowForward(iface string) (chains int, undo func() error, err error) {
	c, err := nftables.New()
	if err != nil {
		return 0, nil, fmt.Errorf("wg: nftables: %w", err)
	}
	targets, err := dropForwardChains(c)
	if err != nil {
		return 0, nil, err
	}
	var touched []*nftables.Chain
	for _, ch := range targets {
		rules, err := c.GetRules(ch.Table, ch)
		if err != nil {
			return 0, nil, fmt.Errorf("wg: list %s/%s: %w", ch.Table.Name, ch.Name, err)
		}
		if findForwardAccept(rules, iface) != nil {
			continue
		}
		c.InsertRule(&nftables.Rule{Table: ch.Table, Chain: ch, Exprs: forwardAcceptExprs(iface)})
		touched = append(touched, ch)
	}
	if len(touched) > 0 {
		if err := c.Flush(); err != nil {
			return 0, nil, fmt.Errorf("wg: insert forward accept for %s: %w", iface, err)
		}
	}
	undo = func() error {
		c, err := nftables.New()
		if err != nil {
			return fmt.Errorf("wg: nftables: %w", err)
		}
		var errs []error
		for _, ch := range touched {
			rules, err := c.GetRules(ch.Table, ch)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if r := findForwardAccept(rules, iface); r != nil {
				errs = append(errs, c.DelRule(r))
			}
		}
		if err := c.Flush(); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	return len(touched), undo, nil
}

// dropForwardChains lists base chains on the forward hook with a drop
// policy in IPv4 or inet tables other than Thawr's.
func dropForwardChains(c *nftables.Conn) ([]*nftables.Chain, error) {
	chains, err := c.ListChains()
	if err != nil {
		return nil, fmt.Errorf("wg: list chains: %w", err)
	}
	var out []*nftables.Chain
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name == nftTable || ch.Hooknum == nil || ch.Policy == nil {
			continue
		}
		if ch.Table.Family != nftables.TableFamilyIPv4 && ch.Table.Family != nftables.TableFamilyINet {
			continue
		}
		if *ch.Hooknum != *nftables.ChainHookForward || *ch.Policy != nftables.ChainPolicyDrop {
			continue
		}
		out = append(out, ch)
	}
	return out, nil
}

// forwardAcceptExprs is `iifname <iface> oifname <iface> accept`.
func forwardAcceptExprs(iface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// findForwardAccept returns the rule that forwardAcceptExprs(iface)
// produced, if rules contains one.
func findForwardAccept(rules []*nftables.Rule, iface string) *nftables.Rule {
	want := forwardAcceptExprs(iface)
	for _, r := range rules {
		if len(r.Exprs) != len(want) {
			continue
		}
		match := true
		for i, e := range r.Exprs {
			switch w := want[i].(type) {
			case *expr.Meta:
				m, ok := e.(*expr.Meta)
				match = ok && m.Key == w.Key
			case *expr.Cmp:
				cmp, ok := e.(*expr.Cmp)
				match = ok && cmp.Op == w.Op && bytes.Equal(cmp.Data, w.Data)
			case *expr.Verdict:
				v, ok := e.(*expr.Verdict)
				match = ok && v.Kind == w.Kind
			}
			if !match {
				break
			}
		}
		if match {
			return r
		}
	}
	return nil
}
