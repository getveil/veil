package cli_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/cli"
	"github.com/getveil/veil/internal/proxy"
	"github.com/getveil/veil/internal/vault"
)

func TestMapRunError(t *testing.T) {
	cases := []struct {
		name   string
		in     error
		expect string
	}{
		{"vault open", fmt.Errorf("wrap: %w", vault.ErrOpen), "Cannot decrypt vault"},
		{"master key", fmt.Errorf("wrap: %w", vault.ErrMasterKey), "Cannot decrypt vault"},
		{"ca load", fmt.Errorf("wrap: %w", proxy.ErrCALoad), "CA certificate"},
		{"listen", fmt.Errorf("wrap: %w", proxy.ErrListen), "Another instance"},
		{"default", errors.New("random failure"), "run failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cli.MapRunErrorForTest(tc.in)
			if !strings.Contains(got, tc.expect) {
				t.Fatalf("expected %q in %q", tc.expect, got)
			}
		})
	}
}
