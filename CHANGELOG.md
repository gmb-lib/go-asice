# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency — what changed, and what it means for code that already
uses it.

## v1.6.2

No library code changed since v1.6.1, so nothing this library does behaves differently. There is
one thing to act on before you bump: **it now needs Go 1.27**.

### Changed

- **The module declares `go 1.27.0`** (was `1.26.6`), so your own module has to be on Go 1.27
  before it can build against this one. A dependency's `go` line does **not** make the go command
  fetch a newer toolchain for you — measured both ways: a consumer whose own `go` directive is
  lower stops with a `requires go >= 1.27.0 (running go 1.26.6)` error, and it stops there with
  `GOTOOLCHAIN` on its `auto` default just as it does under `local`. Raise your own `go` directive
  to `1.27.0` first; from there the go command downloads and uses the 1.27 toolchain by itself, so
  nobody has to install Go by hand. CI that reads `go-version-file: go.mod` follows the bump with
  no workflow edit — a workflow naming a Go version in the YAML needs that line changed.

  This library still has **no module dependencies at all**: the standard library is the whole
  dependency surface, as it has been since v1.2.0.

### Notes

- **The copyright holder is now named in full** — `SIA "Go Make Bytes"` instead of
  `go-make-bytes`. Same MIT licence, same terms; only the holder's legal name is spelled out. Worth
  a glance if you carry the licence text in a notices file.

- The repository gained the open-source kit it was missing — `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, a secret-scan configuration and the README sections pointing at them —
  plus this file. The advisory DCO workflow was removed now that the sign-off is enforced by the
  organisation's app together with a branch ruleset; what a contribution has to carry is unchanged.
  CI now also runs on pushes to `develop`, and its `setup-go` and `golangci-lint` pins were rolled
  forward. No code changed with any of it.

- The gate is green on Go 1.27: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` with **0 races**; `govulncheck` finds nothing.

---

The entries below were **reconstructed from git history** rather than written at the time, so they
say what each tag contains, not why it was decided. They cover what a consumer would have to act on;
releases that only moved build plumbing are named as such.

## v1.6.1

Housekeeping. No library code changed — the `go` directive moved to 1.26.6 and the CI workflows
were reworked.

## v1.6.0

Additive: existing code compiles and behaves unchanged.

### Added

- **`BuildUnsigned(docs []File) ([]byte, error)`** assembles a signature-less `.asice` — mimetype,
  data objects and manifest, with no `signatures*.xml`. It fixes the data-object order up front, so
  the first signature is then added exactly like any parallel one, through `AddSignature` or
  `CoSign`. This is what lets a container exist before anyone has signed it.

- **Document names are validated** when a container is built: safe, non-reserved and unique, with
  `ErrBadDocumentName` when they are not. A name that would escape the container, or collide with a
  reserved entry, is refused at build time rather than producing a container a reader has to defend
  against.

## v1.5.0

Behaviour arrives on bump with nothing to opt into: **every container-reading function now
decompresses under limits**, so a crafted archive cannot exhaust memory.

### Added

- **Decompression limits.** `Limits` (`MaxEntryBytes`, `MaxTotalBytes`, `MaxEntries`),
  `DefaultLimits`, and the `WithLimits(Limits) Option` that overrides them per call. Enforcement
  wraps the readers themselves, so the ZIP headers' declared sizes are never trusted. Two new
  sentinels report a breach: **`ErrTooLarge`** (decompressed content exceeds a cap) and
  **`ErrTooManyEntries`**.

- **`Sniff(data []byte) error`** — a strict outer-shape check for untrusted bytes: ZIP magic at
  offset 0, which rejects prefixed and polyglot files, plus a `mimetype` first entry stored
  uncompressed carrying the exact ASiC-E media type. Shape only; no signature or crypto checks.
  **`IsZip(data []byte) bool`** answers the narrower "is this a ZIP at all" question.

### Changed

- `Inspect`, `DataObjects`, `ExtractSignatures`, `AddSignature`, `CoSign` and `AddDocuments` all
  read under `DefaultLimits` unless you pass your own. A container larger than those defaults that
  used to be read now returns `ErrTooLarge` or `ErrTooManyEntries` — raise the caps with
  `WithLimits` where that is legitimate traffic rather than removing the guard.

## v1.4.0

No new API. One change is visible to code that inspects errors.

### Changed

- **The XAdES parse errors wrap their cause instead of formatting it.** `ErrMalformedXAdES` was
  joined to the underlying XML error with `%v`, which flattened it into text; it now uses `%w`, so
  `errors.Is` and `errors.As` reach the `encoding/xml` error underneath. Code matching on
  `ErrMalformedXAdES` is unaffected — that half already worked.

- Build plumbing otherwise: the CI workflows were extended, dependency review added, and the `go`
  directive moved to 1.26.5.

## v1.3.0

Additive: existing code compiles and behaves unchanged. This is the release that made **fileless
(hash-only) signing** a one-call job instead of a sequence the caller had to assemble.

### Added

- **`CoSign(original, fileless []byte) ([]byte, error)`** adds the signature(s) carried by a
  fileless container — the hash-only result a signing service returns when it never held the file
  bytes — as parallel co-signature(s) on an existing, complete container. It is the one-call form
  of `ExtractSignatures` followed by `AddSignature`, so the caller never has to crack the fileless
  result itself. The co-signature has to reference exactly the data objects the original already
  holds (same filenames, same digests) or the call fails with `ErrSignatureTargetMismatch`; the
  original's data objects and prior signatures are copied byte for byte, so signatures that were
  valid stay valid.

- **`DataObjects(container []byte) ([]File, error)`** returns the container-root data objects with
  their bytes — use it to recompute the digests a co-signature has to reference.

### Fixed

- **Namespace injection no longer breaks the XML it repairs.** `injectNamespaces` formatted the
  inherited namespace declarations incorrectly when splicing them into a signature element.

## v1.2.0

Initial code. The reusable ASiC-E packaging core: `BuildContainer`, `AddSignature`, `Inspect`,
`CheckReferences`, `ExtractSignatures` and `AddDocuments`, working over digests and XAdES
references only — no network I/O, no authentication, no HTTP, and no cryptographic signature
verification, which is delegated to an external validator.
