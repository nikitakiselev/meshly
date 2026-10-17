// Package fault provides fault injection points for integration tests.
// Production builds compile Point to a no-op; binaries built with the
// "meshly_faultinject" tag read MESHLY_FAULT="<point>=<error|crash>[,...]".
package fault

import "errors"

// ErrInjected is returned by an injected error.
var ErrInjected = errors.New("injected fault")
