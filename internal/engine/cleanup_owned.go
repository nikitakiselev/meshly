package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/nikitakiselev/meshly/internal/model"
)

// CleanupOwned tears down leftover kernel state when no trustworthy config
// names the interface. All owned traffic paths must disappear before the
// shared firewall and its integration rules may be removed.
func (e *Engine) CleanupOwned(ctx context.Context) error {
	names, err := e.Links.OwnedInterfaces()
	if err != nil {
		return cleanupFailure(err)
	}
	var errs []error
	for _, name := range names {
		l, err := e.Links.Observe(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("observe %s: %w", name, err))
			continue
		}
		if !l.Owned() {
			continue
		}
		e.progress("close leftover interface %s", name)
		downErr := e.Links.SetDown(name)
		if err := e.Links.Delete(name); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", name, errors.Join(downErr, err)))
			// Keep trying to close traffic even when the link cannot be removed.
			if err := e.WG.RemoveAllPeers(name); err != nil {
				errs = append(errs, fmt.Errorf("remove peers from %s: %w", name, err))
			}
		}
	}
	// A failed dump or any surviving owned link prevents firewall removal.
	remaining, err := e.Links.OwnedInterfaces()
	if err != nil {
		errs = append(errs, err)
	} else if len(remaining) != 0 {
		errs = append(errs, fmt.Errorf("owned interfaces remain: %v", remaining))
	}
	if err := errors.Join(errs...); err != nil {
		return cleanupFailure(err)
	}
	_, err = e.Reconcile(ctx, nil, model.DefaultInterface, nil)
	return err
}

func cleanupFailure(err error) error {
	return &ownedCleanupError{apply: &ApplyError{Cause: err, SafeMode: true, Forward: true}}
}

// Preserve the stable safe-mode exit code without claiming an interface was
// removed when discovery or closure could not be verified.
type ownedCleanupError struct{ apply *ApplyError }

func (e *ownedCleanupError) Error() string {
	return fmt.Sprintf("SAFE MODE: owned-interface cleanup failed: %v; protective firewall retained; VPN path removal could not be verified", e.apply.Cause)
}
func (e *ownedCleanupError) Unwrap() error { return e.apply }
