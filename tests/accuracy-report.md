# Non-PHP corpus accuracy audit

`tests/corpus-result.json` was generated with local IDA 9.4 and compared with
the independently reviewed roots in `tests/ground_truth.json`.

Scoring rules:

- A semantic true positive must identify the same vulnerability root and the
  same primitive. One plugin group can match at most one ground-truth root.
- Site counts expand grouped `occurrences` and `related_eas`.
- There is no meaningful true-negative universe for arbitrary instructions,
  so the useful metrics are precision, recall, and F1.
- One extra `embedded_httpd` related site (`0x40178c`) is part of the same
  unterminated-path chain but is not listed as a canonical ground-truth sink.
- `darkheap:0x1407` is a plausible additional unterminated-input read, but it
  is outside the frozen manual labels and is therefore conservatively counted
  as a false positive here.

| Case | Ground truth roots/sites | Plugin groups/sites | Semantic TP roots/sites | Unmatched groups/sites |
|---|---:|---:|---:|---:|
| chr | 2 / 3 | 2 / 3 | 2 / 3 | 0 / 0 |
| anime | 1 / 1 | 1 / 1 | 1 / 1 | 0 / 0 |
| ezheap | 3 / 3 | 3 / 3 | 3 / 3 | 0 / 0 |
| embedded_httpd | 2 / 2 | 2 / 3 | 2 / 2 | 0 / 1 |
| broken_manager | 2 / 4 | 2 / 4 | 2 / 4 | 0 / 0 |
| catchme | 1 / 1 | 1 / 1 | 1 / 1 | 0 / 0 |
| easy_rw | 3 / 3 | 3 / 3 | 3 / 3 | 0 / 0 |
| easy_rw_proxy | 1 / 1 | 1 / 1 | 1 / 1 | 0 / 0 |
| minidb | 1 / 1 | 1 / 1 | 1 / 1 | 0 / 0 |
| darkheap | 1 / 1 | 2 / 2 | 1 / 1 | 1 / 1 |
| loginsystem | 1 / 2 | 2 / 2 | 1 / 2 | 0 / 0 |
| **Total** | **18 / 22** | **20 / 24** | **18 / 22** | **1 / 2** |

The two LoginSystem copy sites are one manually labelled vulnerability root;
the plugin deliberately keeps them as two actionable groups because they are
independent destination arrays. Both groups are semantically correct, while
the root-recall column counts the underlying vulnerability only once.

## Metrics

Semantic, root/group level:

- Matched plugin groups=19, FP=1, FN=0
- Precision: 19/20 = **95.00%**
- Recall: 18/18 = **100.00%**
- F1: **97.44%**
- At least one semantic hit: **11/11 binaries (100.00%)**

Semantic, concrete-site level:

- TP=22, FP=2, FN=0
- Precision: 22/24 = **91.67%**
- Recall: 22/22 = **100.00%**
- F1: **95.65%**

## What changed from the frozen baseline

The previous baseline was 6/17 roots with 52 groups (11.54% precision,
35.29% recall). The main improvements are:

- must-NUL C-string tracking and cross-function string-consumer summaries;
- statement-ordered `strtok` sessions: null continuation calls preserve the
  active input origin through local aliases, format effects, and return-taint
  summaries, while a clean non-null reset replaces the prior session;
- floating string conversions (`strtof`/`strtod`/`strtold`) as NUL-consuming,
  conditional taint pass-throughs, preserving hostile numeric provenance into
  later integer casts and byte-count sinks without tainting constant inputs;
- source-side copy reads and sibling protocol-field mismatch detection;
- both fixed-length `memcmp` source reads, including symbolic heap bounds and
  interprocedural read effects, while keeping them separate from bounded,
  early-terminating string comparisons;
- `bcmp` as the same two-source fixed-range contract, plus bounded
  `memchr`/`memrchr` source reads and exact encoded literal-storage capacity;
- aggregate `writev`/`pwritev` source reads covering both the descriptor array
  and every payload, interprocedural wrappers, short-input tail disclosure,
  and type-checked reconstruction of iovec entries split into adjacent
  Hex-Rays stack lvars;
- aggregate `readv`/`preadv` destination writes with the same descriptor and
  split-lvar proofs, wrapper and trusted-handle propagation, external-input
  taint, full-object unterminated-string state, and fail-closed Linux
  `IOV_MAX`/`SSIZE_MAX` validation before payload access;
- Linux `sendmsg`/`recvmsg` and `sendmmsg`/`recvmmsg` message effects with
  32/64-bit `msghdr`/`mmsghdr` layouts, header reads, per-entry `msg_len`
  writes, bounded `msg_name`/`msg_control` ranges, nested iovec recovery,
  wrapper propagation, receive taint/termination state, and kernel-ordered
  rejection/clamping semantics (including the sendmmsg-only `vlen` cap);
- bounded `strnlen`/`strndup` scans and pairwise `strncmp`/`strncasecmp`
  comparisons, using the explicit count, path ranges, symbolic allocation
  products, or a proven peer NUL as independent safe upper bounds; both count
  and peer proofs survive interprocedural C-string read summaries;
- stack-clash/split-lvar physical-span recovery;
- pointer-alias-only lifecycle summaries and CFG generation strong updates;
- field-sensitive lifetime locations and call-before-result ordering for realloc;
- bounded strlen narrowing proofs for zero-initialized, width-limited scans;
- a strict fixed-inline-window `Content-Length` receive rule;
- zero-size subtraction and never-defined outbound length checks;
- refcount-policy inconsistency detection;
- custom pool-release recognition for retained indexed global slots;
- indirect-call target extraction and retained-free global control-flow sinks;
- stripped static glibc IFUNC memory-copy fingerprinting;
- stripped static-runtime provenance recovery from strong source markers with
  protected interaction boundaries and callee-only propagation;
- address-preserving buffer aliases and physical stack-span proofs that reject
  decompiler-split lvar and loaded-global-pointer false positives, including
  dynamic copies whose path upper bound fits the compiler-allocated span;
- statement-path guard proofs for signed lengths, subtraction underflow,
  integer narrowing, table indexes, and IFUNC copy bounds; assignments retain
  branch-polarized ctree predicates, while early return/noreturn rejection
  paths negate the full guard conjunction only until a scalar, field, or
  reaching value-preserving alias is reassigned;
- collision-free guard attachment by stable printed-ctree item index, with a
  real IDA fixture covering same-address assignments and negative-polarity
  `else` stores;
- integer value proofs for constant masks, wide aggregate lane extraction,
  checked `ssize_t` error sentinels, and unsigned min/clamp idioms without
  treating merge-only or disjunctive conditions as path facts;
- field-sensitive taint for constant record slots and trailing inline input
  regions, with conservative whole-object fallback for dynamic aliases;
- short-circuit evaluation guards, normalized compound assignments, direct
  unmerged CFG-edge polarity, and a bounded-I/O cursor invariant for canonical
  `recv(base + cursor, capacity - cursor)` loops;
- same-site root-cause subsumption, so the structural inline-window overflow
  rule replaces its generic signed-size symptom without hiding independent
  integer findings;
- affine symbolic allocation/write and allocation/read comparison for
  `malloc`, `calloc`, `realloc`, `reallocarray`, and `aligned_alloc`, with
  unique reaching-definition, alias-offset, dependency stability, allocator
  wrapper summaries, mmap page-rounding checks, and interprocedural
  `write`/`send`/`fwrite` source-read summaries;
- exact constant byte displacements on wrapper pointer arguments, including
  composition across multiple summary layers and negative-start range checks;
  dynamic displacements are rejected, and an explicit Hex-Rays pointer-type
  fact prevents scalar `size + constant` arithmetic from becoming an object
  address (the minidb precision gate freezes this distinction);
- typed scalar templates for allocation and I/O summaries, preserving
  addition/subtraction, constant scaling/shifts, narrowing casts, result width,
  and signedness across multiple wrappers. Bounded read-like return values use
  their successful request-size ceiling for positive-overflow classification,
  while the negative failure sentinel remains a separate conversion concern;
- path-sensitive input error-return contracts and `ERR-001`: a known `-1`
  sentinel crosses reader wrappers and unconditional output-parameter stores,
  including nested wrappers whose caller passes the address of an exact record
  field. Output summaries retain the finite wrapper statuses possible while
  the sentinel is present; only caller guards that reject every such status
  discharge the output chain. Direct return passthrough preserves the relation;
  ternary, comparison/boolean, and constant multi-return mappings are evaluated
  under the output-sentinel hypothesis. Guarded scalar assignments merge at a
  return only when a definite base or complementary branch pair covers every
  path; optional overrides retain all finite values and incomplete definitions
  remain unknown. Calls visited after their containing
  Condition or Return expression use that expression's logical execution point.
  Caller guards reinterpret zero-extended ARM64 W0 status patterns at the
  recovered width and can evaluate Hex-Rays sign-bit-mask rewrites. Output effects retain their statement origin
  and are removed only when every later CFG path contains an overlapping write.
  Known read-only calls, zero-byte writes, sibling fields, and analyzed pure
  internal functions preserve the contract; partial/exact overlaps and unknown
  pointer-taking calls clobber it. Deterministic bounded writers carry a
  separately proven must-write prefix through wrappers: an unresolved dynamic
  length remains zero-capable, while type-correct path lower bounds and
  complementary CFG writes can prove an all-path clobber. Summary-time path
  facts include terminating-branch complements and unmerged predecessor edges;
  relevant redefinitions invalidate them while unaffected conjuncts survive.
  Excluding an integer type boundary with `!=` tightens only that boundary, so
  an unsigned `n != 0` proves a one-byte prefix without general disequality
  guessing. Known may-write APIs remain separate from strong clobbers:
  read/recv/fread/getrandom can return zero or fail, scanf can perform no
  conversions, and other non-deterministic bounded writes expose only a
  request ceiling. Their taint and write summaries still cross wrappers, but
  they cannot erase an older error output solely from a positive request size;
  deterministic memset/memcpy-family effects continue to use must-write
  prefixes. The observed
  same-width unsigned value must uniquely reach an
  allocation, byte-count, aggregate-count, or array-index sink. Same-object
  sibling fields remain independent, while exact redefinitions, possible
  pointer-write clobbers, and signed/unsigned sentinel rejection on the sink
  path discharge the chain. Aliases and explicit casts remain visible, the
  bounded successful result suppresses an unrelated positive `INT-005`, and
  the generic `INT-002` duplicate is suppressed;
- dependency-driven summary fixed points that recompute only dirty callers
  after a callee changes, with iteration/recomputation/time counters exposed in
  headless scan statistics;
- glibc 2.38+ C23 scanf/strto ABI alias normalization and fortify-wrapper
  semantics: trusted object-size checks fail closed before destination access,
  disabled or tainted checks conservatively fall back to the base API, while
  executable source reads, external-input taint, and summaries are preserved;
- fortified raw-input termination state through custom `WriteEffect` wrappers:
  executable exact-object reads reach later C-string consumers, while a proven
  `__read_chk` abort dominates and suppresses the unreachable consumer even
  when an older raw write had already made the destination unterminated;
- authoritative direct libc/fortify models when a decompilable implementation
  is present, preventing a local `__read_chk` body from being composed again as
  an unguarded `read`; targeted Hex-Rays type priming is limited to immediate
  local fortify wrappers and their callers so unrelated call-graph types remain
  stable, including binaries whose external debug bundle is absent;
- exact Linux x86-64 stack-guard adjacency as a machine-level NUL disproof:
  a byte array must end exactly where an lvar loaded from `FS:0x28` begins, and
  only an exact-capacity write may use glibc's cleared low canary byte. Larger
  writes still invalidate the sentinel and retain overflow/string findings;
- unbounded string fortify writes (`__strcpy_chk`, `__stpcpy_chk`, and
  `__strcat_chk`) with object-size-preserving wrapper summaries: active checks
  suppress destination findings, while `SIZE_MAX` or tainted checks fall back
  to their ordinary unbounded-write models without hiding source NUL scans;
- bounded string fortify writes (`__strncpy_chk`) with object-size-preserving
  read and write summaries: an active failing check suppresses both the
  unreachable destination write and its later source read, an executable read
  still reports source overrun, and `SIZE_MAX` falls back to `strncpy`; known
  incomplete three-argument IDA import types are corrected before IR extraction
  so the fourth ABI object-size argument cannot disappear from Hex-Rays ctree;
- fortified unbounded formatting (`__sprintf_chk` and `__vsprintf_chk`) with
  object-size, literal-format, and resolvable-vararg preservation through write
  summaries; pure text and escaped percent directives retain exact byte sizes,
  while disabled checks fall back without suppressing `%s` source scans;
- literal printf-family narrow-string argument recovery across ordinary,
  starred-width, and POSIX positional directives, with static precision-aware
  source bounds and maximum-preserving wrapper summaries; dynamic precision
  uses type, reaching-definition, and path ranges and is safe only when proven
  nonnegative and within the source capacity, while opaque `va_list` entry
  points are not guessed;
- short-input tail disclosure detection for uninitialized stack/malloc
  objects, with return-value, full-read guard, preinitialization, multiple
  fill, CFG reachability, and output-wrapper safety checks;
- cumulative source-read summaries for chunked output loops: a zero-based
  cursor, parameterized loop total, matching `source + cursor`, remaining
  chunk definition, and `cursor += chunk` update are all required before
  exporting the aggregate range. Dynamic source bounds reuse caller path
  guards, and multi-factor `fread`/`fwrite` lengths multiply independently
  bounded factors instead of treating their tightest individual bound as the
  byte count;
- unsigned allocation-addition wrap detection using the actual arithmetic
  width, path upper bounds, narrowing casts, masks/moduli, and reaching local
  definitions;
- width- and signedness-aware allocation/I/O scaling: explicit products and
  left shifts retain their intermediate expression domain and recursively
  combine `add/sub/mul/shl` intervals. Checked implicit products in calloc and
  reallocarray do not emit overflow findings; explicit argument arithmetic
  still does. Dynamic shifts require a valid shift-count interval and signed
  shifts require a nonnegative left operand. The real IDA fixture freezes
  wrapping 32-bit multiplication/`shl`, checked allocators, and safe widened,
  guarded, or unsigned-derived counterparts;
- exact SHA-256 matching of vulnerable runtime converter sidecars.

The `broken_manager` labels now also include the independently re-reviewed
delete handler: `sub_177F` releases `unk_50C0[index]` while only the separate
size array is cleared, leaving show and repeated delete on a dangling slot.

The remaining conservative extra is `darkheap:0x1407`. The implementation
does not suppress it merely to fit this corpus: `read(..., 32)` exactly fills a
zeroed 32-byte region before `strtol`, so a missing NUL is a defensible review
candidate even though it was not selected as an exploitable root in the manual
answer set.
