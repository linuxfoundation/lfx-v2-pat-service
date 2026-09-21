// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import "strings"

// AllowList names the principals permitted to call the validate endpoint. An empty list allows nobody, so a
// deployment that forgets to configure it fails closed.
type AllowList struct {
	principals map[string]struct{}
}

// NewAllowList parses a comma-separated list of principals, trimming whitespace and ignoring empty entries.
func NewAllowList(raw string) AllowList {
	a := AllowList{principals: map[string]struct{}{}}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			a.principals[p] = struct{}{}
		}
	}
	return a
}

// Allowed reports whether principal may validate secrets.
func (a AllowList) Allowed(principal string) bool {
	_, ok := a.principals[principal]
	return ok
}

// Len returns the number of allowed principals, for startup logging.
func (a AllowList) Len() int {
	return len(a.principals)
}
