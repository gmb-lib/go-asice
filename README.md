# asice

A small, framework-agnostic Go library for assembling and inspecting **ASiC-E**
(`.asice`) containers that hold **XAdES** signatures, per
[ETSI EN 319 162-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.00_30/en_31916201v010100v.pdf)
(ASiC) and ETSI EN 319 132-1 (XAdES).

```
go get github.com/gmb-lib/asice
```

It is the reusable packaging core. By design it does **no network I/O, no authentication, no
HTTP**, and performs **no cryptographic signature verification** — that SHALL BE
delegated to an external validator (example: `EU DSS`). The only checks here are
over **file digests and XAdES references** (hashing + XML reading), which keeps
the dependency surface to the standard library.

## API

| Function | Purpose |
|---|---|
| `BuildContainer(docs, signatures, opts) ([]byte, error)` | Assemble a new `.asice` from 1..N documents + 1..N XAdES signatures. |
| `AddSignature(container, newSignature) ([]byte, error)` | Add a parallel (co-) signature to an existing `.asice`; derives the next `signatures*.xml` index itself. |
| `CoSign(original, fileless) ([]byte, error)` | Add the signature(s) from a fileless (hash-only) container as parallel co-signature(s) on a complete container; one-call `ExtractSignatures` + `AddSignature`. |
| `AddDocuments(container, docs) ([]byte, error)` | Complete a fileless (hash-signed) container by inserting the data objects; verifies filename and digest before inserting. |
| `ExtractSignatures(container) ([]File, error)` | Return the `signatures*.xml` entries from a container (including a fileless one); output is suitable for `AddSignature`. |
| `DataObjects(container) ([]File, error)` | Return the container-root data objects (signed files) with their bytes; use to recompute the digests a co-signature must reference. |
| `Inspect(container) (Manifest, []SignatureInfo, []DataObject, error)` | Enumerate manifest, signatures, and data objects. |
| `CheckReferences(docs, signatures) error` | Verify signatures reference exactly the supplied documents (count + filename + SHA-2 digest). |
| `Sniff(data) error` | Strict outer-shape check for untrusted bytes: ZIP magic at offset 0 (rejects prefixed/polyglot files) + a `mimetype` first entry, stored uncompressed, with the exact ASiC-E media type. Shape only — no signature or crypto checks. |
| `IsZip(data) bool` | ZIP local-file-header magic at offset 0 (byte check only). Combine with `Sniff` to tell "plain ZIP" apart from "ASiC-E". |

### Reading untrusted containers — decompression limits

Every container-reading function (`Inspect`, `DataObjects`, `ExtractSignatures`,
`AddSignature`, `CoSign`, `AddDocuments`, `Sniff`) decompresses entries under
**limits**, so a crafted archive (a "zip bomb") cannot exhaust memory: a
per-entry cap, a total cap across the operation, and an entry-count cap.
Enforcement wraps the readers themselves — the ZIP headers' declared sizes are
never trusted. Defaults (`DefaultLimits`: 64 MiB per entry, 128 MiB total,
512 entries) suit real containers; override per call:

```go
_, _, _, err := asice.Inspect(data, asice.WithLimits(asice.Limits{MaxEntryBytes: 8 << 20}))
// errors.Is(err, asice.ErrTooLarge) / errors.Is(err, asice.ErrTooManyEntries)
```

A non-positive field in `WithLimits` keeps its default, so raising one limit
never silently disables the others.

### Example

```go
docs := []asice.File{
    {Name: "contract.pdf", Data: pdfBytes},
}
sigs := []asice.File{
    {Name: "xades.xml", Data: xadesBytes}, // detached XAdES from CSC / wallet
}

// Optional: validate references explicitly (BuildContainer also does this
// unless BuildOptions.SkipReferenceCheck is set).
if err := asice.CheckReferences(docs, sigs); err != nil {
    log.Fatal(err)
}

container, err := asice.BuildContainer(docs, sigs, nil)
if err != nil {
    log.Fatal(err)
}
// `container` is the raw .asice — hand it to external validation service to validate.

// Later, a second party co-signs the same data objects:
updated, err := asice.AddSignature(container, secondXadesBytes)
```

## What it produces

A standards-shaped ASiC-E ZIP:

- `mimetype` — **first entry, stored uncompressed**, value
  `application/vnd.etsi.asic-e+zip`, written with a clean local header (no data
  descriptor) so it can be read as the container's leading bytes.
- the original document(s) in the container root.
- `META-INF/manifest.xml` — OpenDocument-style manifest; root file-entry
  media-type is always the ASiC-E type, then one entry per data object.
- `META-INF/signatures0.xml`, `signatures1.xml`, … — each a `XAdESSignatures`
  wrapper around one detached `ds:Signature`. (No `ASiCManifest.xml`: for the
  XAdES profile the per-file references live inside the signature.)

`AddSignature` copies all existing entries **byte-for-byte** (preserving
compressed bytes and CRC) and only appends a new signature file, so previously
valid signatures are never disturbed. The input container is treated as
immutable.

### National profile: validated-by-construction

The library does not hand-tune profile specifics beyond the manifest rule above.
A container is considered conformant once it passes validation through external validation service, `EU DSS` for example. 

## Errors

Mismatches return sentinel errors (use `errors.Is`):

`ErrFileCountMismatch`, `ErrFilenameMismatch`, `ErrDigestMismatch`,
`ErrSignatureTargetMismatch` (parallel signing), `ErrMalformedXAdES`,
`ErrUnsupportedDigest`, `ErrInvalidContainer`, `ErrNoDocuments`,
`ErrNoSignatures`, `ErrTooLarge` / `ErrTooManyEntries` (decompression limits).

## Scope / non-goals

- No key handling, no signature *creation* — the signer signs externally
  (wallet / CSC / own tools).
- No in-process signature cryptography — validation SHALL BE delegated to external validation service, `EU DSS` for example.
- Countersignatures are out of scope (parallel/co-signatures only).
