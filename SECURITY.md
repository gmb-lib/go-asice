# Security policy

This library assembles and reads **ASiC-E** containers, and it reads them from bytes nobody
trusts. It makes exactly one integrity claim — that the signatures in a container reference
exactly the documents beside them, by name and by digest — and everything downstream, from a
signing service to an archive, acts on that claim. It deliberately makes no cryptographic claim
at all: signature verification belongs to a validator such as EU DSS.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/gmb-lib/go-asice/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- a container or input that triggers it, if you can share one;
- whether you have told anyone else, and whether a disclosure date already binds you.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

- `CheckReferences` reporting that the signatures cover exactly the supplied documents when they do
  not — a filename or digest mismatch that passes. This is the library's one integrity claim, so a
  false pass here is its worst possible failure.
- `AddDocuments` inserting a data object whose bytes do not match the digest the signature
  references, completing a hash-only container with the wrong file.
- `AddSignature` or `CoSign` producing a container in which an existing signature is dropped,
  overwritten or silently renumbered, so a co-signature removes someone else's.
- `Sniff` admitting bytes that are not an ASiC-E — a prefixed or polyglot file, or a `mimetype`
  entry that passes the shape check while the container is something else.
- Entry names reaching a caller as ordinary filenames when they contain a path separator, an
  absolute path, a parent-directory segment or control characters.
- A decompression, entry-count or size limit that can be bypassed, so untrusted bytes cost
  unbounded memory or time.
- XML reading that resolves external entities, or otherwise reaches the network or the filesystem.

Denial of service and findings that need an already-compromised host are in scope but lower
priority. Reports about outdated dependencies are welcome where you can show the vulnerable path
is actually reachable.

## What is deliberately not a finding

This library performs **no cryptographic signature verification**. That a forged or invalid
signature passes through it is by design — nothing here claims the signature is good. A report
that some API *implies* it verified a signature, or that a caller is likely to read it that way,
is a real finding; a report that it failed to detect a bad signature is not.

## Scope

This policy covers the code in this repository. It does not cover the validators, signing services
or applications that consume it — report those to the parties that run them.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
