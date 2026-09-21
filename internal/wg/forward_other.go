//go:build !linux

package wg

import "context"

// routerNAT does nothing off Linux: routers need Linux in this release.
type routerNAT struct{}

func (routerNAT) set(context.Context, FilterSet) error { return nil }

func (routerNAT) remove() error { return nil }
