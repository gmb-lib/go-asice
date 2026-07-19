package asice

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
)

// zipMagic is the ZIP local-file-header signature ("PK\x03\x04"). A genuine
// ASiC-E container starts with it at offset 0; the standard ZIP reader is
// laxer (it locates the central directory from the end of the data), so this
// explicit check also rejects polyglot files that prepend other content to a
// valid archive.
var zipMagic = []byte{0x50, 0x4B, 0x03, 0x04}

// IsZip reports whether data begins with the ZIP local-file-header magic at
// offset 0. It is a byte check only — it does not parse the archive.
func IsZip(data []byte) bool {
	return len(data) >= len(zipMagic) && bytes.Equal(data[:len(zipMagic)], zipMagic)
}

// Sniff checks that data has the strict outer shape of an ASiC-E container,
// per ETSI EN 319 162-1, without reading its documents or signatures:
//
//   - the bytes start with the ZIP magic at offset 0 (no prefixed content);
//   - the archive parses as a ZIP within the configured entry limit;
//   - the first entry is "mimetype", stored uncompressed, with the exact
//     content "application/vnd.etsi.asic-e+zip".
//
// It returns nil for a well-formed container and an error wrapping
// ErrInvalidContainer (or ErrTooManyEntries) otherwise. A plain ZIP that is
// not an ASiC-E container fails the mimetype checks — callers that need to
// tell the two apart can combine Sniff with IsZip.
//
// Sniff is shape-only: it does not confirm the presence of signatures (use
// Inspect) and performs no cryptographic verification.
func Sniff(data []byte, opts ...Option) error {
	if !IsZip(data) {
		return fmt.Errorf("%w: no ZIP magic at offset 0", ErrInvalidContainer)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidContainer, err)
	}
	b := newBudget(effectiveLimits(opts))
	if err := b.checkArchive(zr); err != nil {
		return err
	}
	if len(zr.File) == 0 {
		return fmt.Errorf("%w: empty archive", ErrInvalidContainer)
	}
	first := zr.File[0]
	if first.Name != mimetypePath {
		return fmt.Errorf("%w: first entry is %q, want %q", ErrInvalidContainer, first.Name, mimetypePath)
	}
	if first.Method != zip.Store {
		return fmt.Errorf("%w: mimetype entry is compressed, must be stored", ErrInvalidContainer)
	}
	content, err := readMimetype(first)
	if err != nil {
		return err
	}
	if string(content) != MimeType {
		return fmt.Errorf("%w: mimetype is %q, want %q", ErrInvalidContainer, string(content), MimeType)
	}
	return nil
}

// readMimetype reads the (tiny) mimetype entry with a hard bound of its own —
// it never legitimately exceeds the media-type string.
func readMimetype(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open mimetype: %w", ErrInvalidContainer, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, int64(len(MimeType))+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read mimetype: %w", ErrInvalidContainer, err)
	}
	return data, nil
}
