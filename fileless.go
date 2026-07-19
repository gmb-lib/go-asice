package asice

import (
	"archive/zip"
	"bytes"
	"fmt"
)

// ExtractSignatures returns the signatures*.xml entries from a container,
// including a fileless one. The returned File.Data is suitable to pass to
// AddSignature.
//
// The container is read under the decompression Limits (DefaultLimits unless
// overridden via opts).
func ExtractSignatures(container []byte, opts ...Option) ([]File, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidContainer, err)
	}
	b := newBudget(effectiveLimits(opts))
	if err := b.checkArchive(zr); err != nil {
		return nil, err
	}

	var sigs []File
	for _, f := range zr.File {
		if !isSignatureFile(f.Name) {
			continue
		}
		data, err := b.readEntry(f)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, File{Name: f.Name, Data: data})
	}

	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}
	return sigs, nil
}

// CoSign adds the signature(s) carried by a fileless container — the hash-only
// result a signing service returns when it never held the file bytes — as
// parallel co-signature(s) on an existing, complete container, returning the
// updated container. It is the one-call form of ExtractSignatures followed by
// AddSignature, so the caller never has to crack the fileless result itself.
//
// The co-signature(s) must reference exactly the data objects the original
// container already holds (same filenames and digests); otherwise an error
// wrapping ErrSignatureTargetMismatch is returned. The original's data objects
// and prior signatures are copied byte-for-byte, so previously valid signatures
// remain valid, and each added signature file is given the next free index.
func CoSign(original, fileless []byte, opts ...Option) ([]byte, error) {
	sigs, err := ExtractSignatures(fileless, opts...)
	if err != nil {
		return nil, err
	}
	updated := original
	for _, s := range sigs {
		if updated, err = AddSignature(updated, s.Data, opts...); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// AddDocuments inserts data object(s) into a container that references them but
// is missing their bytes (e.g. a hash-signed, fileless container), producing a
// complete .asice. It verifies that each supplied document matches what the
// container's signatures reference before inserting.
//
// The container is read under the decompression Limits (DefaultLimits unless
// overridden via opts).
func AddDocuments(container []byte, docs []File, opts ...Option) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidContainer, err)
	}
	b := newBudget(effectiveLimits(opts))
	if err := b.checkArchive(zr); err != nil {
		return nil, err
	}

	// Collect all data-object references from every signature in the container.
	refsByName := make(map[string]Reference)
	hasSignatures := false
	for _, f := range zr.File {
		if !isSignatureFile(f.Name) {
			continue
		}
		hasSignatures = true
		data, err := b.readEntry(f)
		if err != nil {
			return nil, err
		}
		parsed, err := parseSignatures(data)
		if err != nil {
			return nil, err
		}
		for _, ps := range parsed {
			for _, ref := range ps.refs {
				refsByName[ref.URI] = ref
			}
		}
	}
	if !hasSignatures {
		return nil, ErrNoSignatures
	}

	// Names of data objects already present in the container.
	presentObjects := make(map[string]bool)
	for _, f := range zr.File {
		if isDataObject(f.Name) {
			presentObjects[f.Name] = true
		}
	}

	// Validate each supplied doc: must be referenced, not already present, and
	// its digest must match what the signature recorded.
	for _, doc := range docs {
		ref, ok := refsByName[doc.Name]
		if !ok {
			return nil, fmt.Errorf("%w: %q is not referenced by any signature in the container",
				ErrFilenameMismatch, doc.Name)
		}
		if presentObjects[doc.Name] {
			return nil, fmt.Errorf("%w: %q is already present in the container",
				ErrFilenameMismatch, doc.Name)
		}
		got, err := digestBase64(ref.Algorithm, doc.Data)
		if err != nil {
			return nil, fmt.Errorf("document %q: %w", doc.Name, err)
		}
		if !digestEqual(got, ref.DigestValue) {
			return nil, fmt.Errorf("%w: document %q", ErrDigestMismatch, doc.Name)
		}
	}

	// After processing, every referenced object must be present (already in the
	// container or among the supplied docs).
	docsByName := make(map[string]bool)
	for _, d := range docs {
		docsByName[d.Name] = true
	}
	for name := range refsByName {
		if !presentObjects[name] && !docsByName[name] {
			return nil, fmt.Errorf("%w: referenced object %q not provided",
				ErrFilenameMismatch, name)
		}
	}

	// Parse the existing manifest so we can supplement it with entries for the
	// new docs (a fileless manifest usually already names them; add only if absent).
	var existingManifest Manifest
	for _, f := range zr.File {
		if f.Name != manifestPath {
			continue
		}
		data, err := b.readEntry(f)
		if err != nil {
			return nil, err
		}
		existingManifest, err = parseManifest(data)
		if err != nil {
			return nil, err
		}
		break
	}
	manifestByPath := make(map[string]bool)
	for _, e := range existingManifest.Entries {
		manifestByPath[e.FullPath] = true
	}
	updatedManifest := existingManifest
	for _, doc := range docs {
		if !manifestByPath[doc.Name] {
			updatedManifest.Entries = append(updatedManifest.Entries, ManifestEntry{
				FullPath:  doc.Name,
				MediaType: mediaType(doc.Name),
			})
		}
	}
	manifestXML, err := updatedManifest.render()
	if err != nil {
		return nil, fmt.Errorf("render manifest: %w", err)
	}

	// Assemble the new container: mimetype first (raw), then new docs, then the
	// updated manifest, then all signature files (raw so they remain valid).
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, f := range zr.File {
		if f.Name == mimetypePath {
			if err := copyRaw(zw, f); err != nil {
				return nil, err
			}
			break
		}
	}
	for _, doc := range docs {
		if err := writeStoredFile(zw, doc.Name, doc.Data, zip.Deflate); err != nil {
			return nil, err
		}
	}
	if err := writeStoredFile(zw, manifestPath, manifestXML, zip.Deflate); err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if !isSignatureFile(f.Name) {
			continue
		}
		if err := copyRaw(zw, f); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("finalise container: %w", err)
	}
	return buf.Bytes(), nil
}
