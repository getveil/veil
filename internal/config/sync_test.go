package config

import (
	"testing"
)

func TestSync_AddsNewCredentials(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"OLD_KEY": {"api.old.com"},
		},
		Ignore:    []string{},
		SkipHosts: []string{},
	}
	vaultEntries := []ScopingEntry{
		{Name: "OLD_KEY", Hosts: []string{"api.old.com"}},
		{Name: "NEW_KEY", Hosts: []string{"api.new.com"}},
	}

	result := Sync(existing, vaultEntries)

	if len(result.Added) != 1 || result.Added[0] != "NEW_KEY" {
		t.Errorf("expected 1 addition (NEW_KEY), got: %v", result.Added)
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removals, got: %v", result.Removed)
	}
	if _, ok := result.Config.Scoping["NEW_KEY"]; !ok {
		t.Error("NEW_KEY should be in synced config")
	}
	if _, ok := result.Config.Scoping["OLD_KEY"]; !ok {
		t.Error("OLD_KEY should be preserved in synced config")
	}
}

func TestSync_RemovesStaleCredentials(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"ALIVE":   {"api.alive.com"},
			"REMOVED": {"api.removed.com"},
		},
		Ignore:    []string{},
		SkipHosts: []string{},
	}
	vaultEntries := []ScopingEntry{
		{Name: "ALIVE", Hosts: []string{"api.alive.com"}},
	}

	result := Sync(existing, vaultEntries)

	if len(result.Removed) != 1 || result.Removed[0] != "REMOVED" {
		t.Errorf("expected 1 removal (REMOVED), got: %v", result.Removed)
	}
	if _, ok := result.Config.Scoping["REMOVED"]; ok {
		t.Error("REMOVED should not be in synced config")
	}
}

func TestSync_PreservesUserHosts(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"MY_KEY": {"custom.host.com", "other.host.com"},
		},
		Ignore:    []string{"test/**"},
		SkipHosts: []string{"*.internal.com"},
	}
	vaultEntries := []ScopingEntry{
		{Name: "MY_KEY", Hosts: []string{"auto.detected.com"}},
	}

	result := Sync(existing, vaultEntries)

	hosts := result.Config.Scoping["MY_KEY"]
	if len(hosts) != 2 || hosts[0] != "custom.host.com" {
		t.Errorf("expected preserved user hosts, got %v", hosts)
	}
	if len(result.Config.Ignore) != 1 || result.Config.Ignore[0] != "test/**" {
		t.Errorf("ignore should be preserved, got %v", result.Config.Ignore)
	}
	if len(result.Config.SkipHosts) != 1 || result.Config.SkipHosts[0] != "*.internal.com" {
		t.Errorf("skip_hosts should be preserved, got %v", result.Config.SkipHosts)
	}
}

func TestSync_NoDrift(t *testing.T) {
	existing := &ProjectConfig{
		Scoping: map[string][]string{
			"KEY_A": {"api.a.com"},
		},
	}
	vaultEntries := []ScopingEntry{
		{Name: "KEY_A", Hosts: []string{"api.a.com"}},
	}

	result := Sync(existing, vaultEntries)

	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Errorf("expected no changes, got added=%v removed=%v", result.Added, result.Removed)
	}
}
