package asice

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
)

// Errors reported by the decompression limits.
// Wrap-aware: use errors.Is against these sentinels.
var (
	// ErrTooLarge: an entry's decompressed content, or the decompressed total
	// across all entries read, exceeds the configured limit. Raised while
	// reading, so memory use stays bounded regardless of what the ZIP headers
	// claim.
	ErrTooLarge = errors.New("asice: decompressed content exceeds limit")
	// ErrTooManyEntries: the archive holds more entries than the configured
	// limit allows.
	ErrTooManyEntries = errors.New("asice: too many archive entries")
)

// Limits bounds the decompression work done while reading a container, so a
// crafted archive (a "zip bomb") cannot exhaust memory. Enforcement wraps the
// entry readers themselves — the ZIP headers' declared sizes are never trusted.
type Limits struct {
	// MaxEntryBytes caps the decompressed size of any single entry read.
	MaxEntryBytes int64
	// MaxTotalBytes caps the decompressed size summed across all entries read
	// in one operation.
	MaxTotalBytes int64
	// MaxEntries caps the number of entries the archive may hold.
	MaxEntries int
}

// DefaultLimits is applied when no Option overrides it: generous for real
// containers, fatal for decompression bombs.
var DefaultLimits = Limits{
	MaxEntryBytes: 64 << 20,  // 64 MiB
	MaxTotalBytes: 128 << 20, // 128 MiB
	MaxEntries:    512,
}

// Option tunes how a container is read. The container-reading entry points
// (Inspect, DataObjects, ExtractSignatures, AddSignature, CoSign, AddDocuments,
// Sniff) accept options; with none given they read under DefaultLimits.
type Option func(*Limits)

// WithLimits overrides the default read limits. A non-positive field keeps its
// default, so a caller raising one limit does not silently disable the others.
func WithLimits(l Limits) Option {
	return func(eff *Limits) {
		if l.MaxEntryBytes > 0 {
			eff.MaxEntryBytes = l.MaxEntryBytes
		}
		if l.MaxTotalBytes > 0 {
			eff.MaxTotalBytes = l.MaxTotalBytes
		}
		if l.MaxEntries > 0 {
			eff.MaxEntries = l.MaxEntries
		}
	}
}

// effectiveLimits resolves the options against the defaults.
func effectiveLimits(opts []Option) Limits {
	eff := DefaultLimits
	for _, o := range opts {
		o(&eff)
	}
	return eff
}

// budget tracks the remaining decompressed-byte allowance across the entries
// read in one operation.
type budget struct {
	limits    Limits
	remaining int64
}

func newBudget(lim Limits) *budget {
	return &budget{limits: lim, remaining: lim.MaxTotalBytes}
}

// checkArchive validates whole-archive properties (entry count) up front.
func (b *budget) checkArchive(zr *zip.Reader) error {
	if b.limits.MaxEntries > 0 && len(zr.File) > b.limits.MaxEntries {
		return fmt.Errorf("%w: %d entries (limit %d)", ErrTooManyEntries, len(zr.File), b.limits.MaxEntries)
	}
	return nil
}

// readEntry decompresses one entry under the per-entry cap and the shared
// total budget, rejecting unsafe paths. It reads at most one byte past the
// applicable limit, so memory stays bounded even when headers lie.
func (b *budget) readEntry(f *zip.File) ([]byte, error) {
	if !safePath(f.Name) {
		return nil, fmt.Errorf("%w: unsafe entry path %q", ErrInvalidContainer, f.Name)
	}
	limit := int64(-1) // -1 = unlimited
	if b.limits.MaxEntryBytes > 0 {
		limit = b.limits.MaxEntryBytes
	}
	if b.limits.MaxTotalBytes > 0 && (limit < 0 || b.remaining < limit) {
		limit = b.remaining
	}
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %w", ErrInvalidContainer, f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	var r io.Reader = rc
	if limit >= 0 {
		r = io.LimitReader(rc, limit+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: read %q: %w", ErrInvalidContainer, f.Name, err)
	}
	if limit >= 0 && int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: entry %q", ErrTooLarge, f.Name)
	}
	if b.limits.MaxTotalBytes > 0 {
		b.remaining -= int64(len(data))
	}
	return data, nil
}
