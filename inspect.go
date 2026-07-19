package asice

import (
	"archive/zip"
	"bytes"
	"fmt"
)

// SignatureInfo describes one ds:Signature found in a container, with the
// signature file it lives in and the data objects it references.
type SignatureInfo struct {
	Path       string      // e.g. META-INF/signatures0.xml
	References []Reference // data objects this signature covers
}

// DataObject describes one container-root data object.
type DataObject struct {
	Name      string
	MediaType string
	Size      int64
}

// Inspect enumerates the contents of an ASiC-E container: its parsed manifest,
// the signatures it holds, and its data objects. It does not validate the
// container cryptographically.
//
// The manifest and signature entries are decompressed under the Limits
// (DefaultLimits unless overridden via opts); data-object bytes are not read —
// only their headers are enumerated.
func Inspect(container []byte, opts ...Option) (Manifest, []SignatureInfo, []DataObject, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return Manifest{}, nil, nil, fmt.Errorf("%w: %w", ErrInvalidContainer, err)
	}
	b := newBudget(effectiveLimits(opts))
	if err := b.checkArchive(zr); err != nil {
		return Manifest{}, nil, nil, err
	}

	var (
		manifest   Manifest
		signatures []SignatureInfo
		objects    []DataObject
	)

	for _, f := range zr.File {
		switch {
		case f.Name == manifestPath:
			data, err := b.readEntry(f)
			if err != nil {
				return Manifest{}, nil, nil, err
			}
			if manifest, err = parseManifest(data); err != nil {
				return Manifest{}, nil, nil, err
			}

		case isSignatureFile(f.Name):
			data, err := b.readEntry(f)
			if err != nil {
				return Manifest{}, nil, nil, err
			}
			parsed, err := parseSignatures(data)
			if err != nil {
				return Manifest{}, nil, nil, fmt.Errorf("%s: %w", f.Name, err)
			}
			for _, ps := range parsed {
				signatures = append(signatures, SignatureInfo{
					Path:       f.Name,
					References: ps.refs,
				})
			}

		case isDataObject(f.Name):
			if !safePath(f.Name) {
				return Manifest{}, nil, nil, fmt.Errorf("%w: unsafe entry path %q", ErrInvalidContainer, f.Name)
			}
			objects = append(objects, DataObject{
				Name:      f.Name,
				MediaType: mediaType(f.Name),
				Size:      int64(f.UncompressedSize64),
			})
		}
	}

	return manifest, signatures, objects, nil
}
