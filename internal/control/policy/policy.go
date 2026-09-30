// Package policy loads, validates and compiles the YAML ACL file: who
// may reach which ports on which peers, evaluated to default deny.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// Version is the only policy file version this binary understands.
const Version = 1

// ErrNotFound is returned by Load when the file does not exist; callers
// treat it as an empty (default deny) policy with a warning.
var ErrNotFound = errors.New("policy: file not found")

// Policy is the loaded ACL document.
type Policy struct {
	Version   int                 `yaml:"version"`
	Groups    map[string][]string `yaml:"groups"`
	TagOwners map[string][]string `yaml:"tagOwners"`
	ACLs      []Rule              `yaml:"acls"`

	// Hash identifies the file contents (first 12 hex of SHA-256);
	// empty for Empty().
	Hash string `yaml:"-"`
	// Source is the raw document as loaded, shown by `admin policy show`.
	Source []byte `yaml:"-"`

	rules []parsedRule
}

// Rule is one accept rule as written in the file.
type Rule struct {
	Action string   `yaml:"action"`
	Src    []string `yaml:"src"`
	Dst    []string `yaml:"dst"`
	Proto  string   `yaml:"proto"`
}

// parsedRule is a Rule with its selectors decoded.
type parsedRule struct {
	src   []Selector
	dst   []Dst
	proto string
}

// Empty returns the default-deny policy used when no file exists.
func Empty() *Policy { return &Policy{Version: Version} }

// Load reads and parses the policy file at path.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes a policy document and checks everything that needs no
// knowledge of the registry: version, actions, selector and port
// syntax, group and tagOwners shapes.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("policy: version %d unsupported (want %d)", p.Version, Version)
	}
	if err := p.parseRules(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	p.Hash = hex.EncodeToString(sum[:6])
	p.Source = append([]byte(nil), data...)
	return &p, nil
}

// parseRules decodes selectors, ports and protocols; errors name the
// offending field.
func (p *Policy) parseRules() error {
	var errs []error
	for name, members := range p.Groups {
		if !validLabel(name) {
			errs = append(errs, fmt.Errorf("groups.%s: name must be a lowercase label", name))
		}
		if len(members) == 0 {
			errs = append(errs, fmt.Errorf("groups.%s: no members", name))
		}
		for i, m := range members {
			if sel, err := ParseSelector(m, false); err != nil || sel.Kind != SelUser {
				errs = append(errs, fmt.Errorf("groups.%s[%d]: %q must be a user name", name, i, m))
			}
		}
	}
	for tag, owners := range p.TagOwners {
		if sel, err := ParseSelector(tag, false); err != nil || sel.Kind != SelTag {
			errs = append(errs, fmt.Errorf("tagOwners.%s: key must be tag:<name>", tag))
		}
		if len(owners) == 0 {
			errs = append(errs, fmt.Errorf("tagOwners.%s: no owners", tag))
		}
		for i, o := range owners {
			if sel, err := ParseSelector(o, false); err != nil || (sel.Kind != SelUser && sel.Kind != SelGroup) {
				errs = append(errs, fmt.Errorf("tagOwners.%s[%d]: %q must be a user or group", tag, i, o))
			}
		}
	}
	p.rules = make([]parsedRule, 0, len(p.ACLs))
	for i, r := range p.ACLs {
		var pr parsedRule
		if r.Action != "accept" {
			errs = append(errs, fmt.Errorf("acls[%d].action: %q must be accept", i, r.Action))
		}
		if len(r.Src) == 0 {
			errs = append(errs, fmt.Errorf("acls[%d].src: at least one selector required", i))
		}
		for j, s := range r.Src {
			sel, err := ParseSelector(s, false)
			if err != nil {
				errs = append(errs, fmt.Errorf("acls[%d].src[%d]: %w", i, j, err))
				continue
			}
			pr.src = append(pr.src, sel)
		}
		if len(r.Dst) == 0 {
			errs = append(errs, fmt.Errorf("acls[%d].dst: at least one host:ports required", i))
		}
		for j, d := range r.Dst {
			dst, err := ParseDst(d)
			if err != nil {
				errs = append(errs, fmt.Errorf("acls[%d].dst[%d]: %w", i, j, err))
				continue
			}
			pr.dst = append(pr.dst, dst)
		}
		proto, err := ParseProto(r.Proto)
		if err != nil {
			errs = append(errs, fmt.Errorf("acls[%d].proto: %w", i, err))
		}
		pr.proto = proto
		if proto == ProtoICMP {
			for j, d := range pr.dst {
				if len(d.Ports) != 1 || d.Ports[0] != AllPorts {
					errs = append(errs, fmt.Errorf("acls[%d].dst[%d]: icmp rules must use port *", i, j))
				}
			}
		}
		p.rules = append(p.rules, pr)
	}
	if len(errs) > 0 {
		return fmt.Errorf("policy: %w", errors.Join(errs...))
	}
	return nil
}

// PeerReferences reports, for every name the policy selects with
// peer:<name>, where it does so ("acls[0].dst[1]"). A peer holding that
// name gets those grants, so renaming it or letting another device take
// the name changes who may reach what.
func (p *Policy) PeerReferences() map[string][]string {
	refs := map[string][]string{}
	for i, r := range p.rules {
		for j, s := range r.src {
			if s.Kind == SelPeer {
				refs[s.Name] = append(refs[s.Name], fmt.Sprintf("acls[%d].src[%d]", i, j))
			}
		}
		for j, d := range r.dst {
			if d.Host.Kind == SelPeer {
				refs[d.Host.Name] = append(refs[d.Host.Name], fmt.Sprintf("acls[%d].dst[%d]", i, j))
			}
		}
	}
	return refs
}
