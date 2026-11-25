# Independent golden specification

`golden-fixtures.json` contains **47 successful cases with full 37-slot numeric vectors, 38 visible failure cases, and 4 typed invariant recipes**. Every string is synthetic. No real URL row, data-derived URL hash, model or extractor contributed expected values. These are specification goldens, not observed behavior of software already claimed correct.

`manual-annotations.json` is the literal author worksheet: each success records manually counted nonzero feature slots, canonical host histogram, raw path histogram, raw components, raw ASCII token sequence and arithmetic explanation. Omitted nonzero-slot keys mean literal zero in the starting 37-zero **worksheet template**, not error zero-fill. The materializer copies these hand-entered numbers, computes entropy only from the hand-entered multiplicities and ratio only from the two hand-entered counts, then emits literal full vectors. It never parses, counts, splits, normalizes or otherwise inspects `input.text`. It accepts no URL-to-feature function and imports no application module. This is pure arithmetic/document materialization permitted by the task.

`checks/materialize_manual_fixture_spec.py` refuses to overwrite `golden-fixtures.json`. Earlier drafts and pre-correction literals are retained under `docs/revisions/`; a future amendment must likewise preserve the previous version. `checks/check_specification.py` checks document/schema/arithmetic self-consistency without deriving expected values from URL strings. Such checks do not replace independent review. The reviewer independently derives spelling counts, H/P character multiplicities, query segments, suffix boundaries and cues from the contract before comparing all 37 expected slots.

A future test adapter should expand typed input tags only: `kind=string` supplies `text`; `kind=json` supplies the exact JSON value; `kind=tagged_nonjson,value_tag=NaN` supplies a floating NaN, not the string `NaN`. Boolean is not a numeric/string input. Invariants I02..I04 describe oversized/surrogate/DNS-length inputs without putting invalid bytes or large strings in this file. I01 describes an internal-output validity check; non-finite values are never valid JSON fixture numbers. No test adapter may compute oracle features from a URL, historical extractor, implementation under test or CSV.

Fixture expected objects omit `contract_version` and `bundle_sha256` to avoid circular file hashing. A future conformance harness supplies these two envelope fields as the literal selected version and externally verified bundle manifest digest; it compares status, error, feature array and metadata against this file. This envelope substitution is not a feature oracle. The manifest hashes named bundle files and excludes itself; the final coordinator evidence records its identity. Error metadata contains every required key with null values. Synthetic worksheets include components that must not be logged for real inputs.

Coverage:

| Cases | Contract concern |
|---|---|
|F01–F08|HTTP/HTTPS, network-path, schemeless recovery and port ambiguity, uppercase, trailing root dot and leading-zero port spelling|
|F09–F11, F37–F38|Validated IPv4/IPv6, IDNA ß nontransitional, mapped Unicode dot, pure-hex canonical embedded IPv4|
|F12–F17, F33, F36, F41|Once versus double decoding, escaped separators, ordered duplicate/blank/bare query pairs, literal plus, nested uppercase scheme, present-empty query, escaped ampersand/equals, decoded space|
|F18–F22, F29–F32, F35, F39–F40|Brand/keyword token boundaries, exact shortener spoof resistance, listed final label, host-length/subdomain cutoffs, punctuation/fragment, hostname hyphen, left-boundary nested scheme negative, multiple # retention|
|F23–F28|co.uk, PRIVATE github.io tenants, *.ck wildcard, !www.ck exception, default * unlisted suffix|
|F34|Nonoverlapping raw // counting and raw P entropy|
|F42–F47|Repeated exact keyword across P/Q/F counts once, raw Unicode versus once-decoded escaped UTF8, exact host-length20 boundary, accepted port0 and65535 endpoints|
|E01–E38|Null/numeric/boolean/NaN inputs, raw forbidden characters, unsupported schemes/userinfo, brackets/unbracketed IPv6, invalid ports/IDNA/IP, zones/IPvFuture, invalid percent/UTF8 in components, precedence, relative reference|
|I01–I04|Visible non-finite internal failure, maximum input bound, surrogate code point, DNS label length|

For entropy, `H=log2(N) - Σ n log2(n)/N`; singleton terms contribute zero. E.g. F01 H has N=6 with multiplicities 2,1,1,1,1, so H=log2(6)-2/6. F34 P has counts 3,2 and H=log2(5)-(3log2(3)+2)/5. Empty or singleton P has entropy0. Full multiplicities and literal decimal results are in JSON; exact integer equality and 1e-12 abs+relative floating agreement apply. Coverage is bounded and cannot prove universal parser correctness; future implementation should add property/fuzz tests under a separate task without changing these independent goldens silently.
