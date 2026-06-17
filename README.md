# Morok

Morok is a modular C++23 LLVM New-PM IR obfuscator. It loads as a pass plugin
inside `clang` or `opt`, rewrites LLVM IR, and emits a behaviourally identical
program with fewer static landmarks, more hostile control/data flow, and layered
runtime self-protection.

The project is deliberately test-first. Pure arithmetic and encoding primitives
live below LLVM and are exercised by exhaustive/property unit tests. The LLVM
passes are tested as IR emitters and then as a whole pipeline by compiling and
running real C/C++ programs clean vs obfuscated.

## Scope

Morok can do things an LLVM pass can produce:

- Rewrite integer, floating, pointer, stack, PHI, branch, call, string, constant,
  vtable, and VM bytecode IR.
- Emit constructors, helper functions, helper threads, inline assembly,
  signal/exception handlers, direct syscalls, and platform-specific runtime
  probes into the target binary.
- Generate per-build and per-callsite diversity from a deterministic seed.
- Emit retained post-link manifests for later patchers where final native bytes
  are needed.

Morok cannot do things that require external infrastructure:

- It cannot sign Mach-O or PE files, provision entitlements, enable HVCI/PPL, or
  turn on compiler/linker features such as CFG/XFG/CET/PAC/BTI/RELRO.
- It cannot provide TPM/SGX/TrustZone/SEV/Secure-Enclave remote roots of trust.
- It cannot make a hostile kernel or hypervisor trustworthy. It raises cost and
  creates tamper-sensitive dependencies inside userland code.

The implementable protection backlog is tracked in
[`docs/insurance-tasks.md`](docs/insurance-tasks.md). Algorithm and pass details
live in [`docs/algorithms.md`](docs/algorithms.md) and
[`docs/hardness.md`](docs/hardness.md).

## Repository Layout

Morok is layered so each level depends strictly downward:

```text
morok::core       Pure algorithms: PRNGs, Feistel, GF(2^8), XOR sharing,
                  MBA/substitution identities, MQ/T-function/Knuth helpers.
                  No LLVM, no I/O.

morok::config     Presets, TOML loading, policy resolution, pass options.
                  No LLVM; demangling is injected.

morok::ir         LLVM helper layer: annotations, symbol cloaking, IR random
                  adapters, shared emit utilities.

morok::passes     New-PM pass implementations plus testable free functions.

libMorok          Loadable New-PM pass plugin and whole-pipeline scheduler.
```

Tracked top-level paths:

```text
include/morok/{core,config,ir,passes,pipeline}/   public headers
src/{core,config,ir,passes,pipeline}/             implementations
tests/{unit,ir,e2e}/                              unit, IR, and e2e gates
programs/                                         local stress corpus, when present
third_party/{doctest,tomlplusplus}/               vendored header-only deps
cmake/Morok{LLVM,Test,Warnings}.cmake             build policy modules
docs/algorithms.md                                pass and scheduler reference
docs/hardness.md                                  primitive hardness notes
docs/insurance-tasks.md                           implementable protection checklist
cross_build.sh                                    Linux/macOS cross-build helper
run_tests.sh                                      authoritative local test entrypoint
```

## Build Requirements

- CMake 3.28 or newer.
- Ninja.
- A C++23 compiler.
- LLVM 18 or newer with the New-PM plugin API Morok targets.

This tree currently validates a forked/custom LLVM plugin API:
`<llvm/Plugins/PassPlugin.h>` with `LLVM_PLUGIN_API_VERSION == 2`. The CMake
probe in [`cmake/MorokLLVM.cmake`](cmake/MorokLLVM.cmake) fails loudly if the
host LLVM cannot load the plugin ABI that Morok was compiled against.

Build:

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DLLVM_DIR="$LLVM_PREFIX/lib/cmake/llvm"
cmake --build build
ctest --test-dir build -j
```

Useful CMake options:

```text
MOROK_BUILD_TESTS=ON       build tests
MOROK_BUILD_PLUGIN=ON      build libMorok
MOROK_WERROR=OFF           treat warnings as errors when ON
MOROK_SANITIZE=OFF         ASan/UBSan for pure layers/tests when ON
```

## Authoritative Test Gate

Use the top-level script unless you are intentionally narrowing the loop:

```sh
./run_tests.sh            # incremental configure/build + entire ctest suite
./run_tests.sh --clean    # remove build/ and configure from scratch
./run_tests.sh -R passes  # ctest name regex
./run_tests.sh -L ir      # ctest label: core/config/ir/e2e/programs/max/unit/aggregate
```

The full gate covers:

| Layer | Test style | Evidence |
|---|---|---|
| `core` | exhaustive/property doctest suites | arithmetic, field, cipher, PRNG, sharing, and identity primitives are correct independently of LLVM |
| `config` | doctest suites | presets, merge precedence, policy resolution, TOML parsing, and error paths |
| `ir` / `passes` | LLVM-linked IR tests | every pass emits verifier-clean IR and actually fires on representative shapes |
| whole pipeline | clean-vs-obfuscated differentials | compiled binaries preserve output across presets/configs/seeds |
| `programs/` corpus | compile and runtime sweeps | real C/C++ programs compile at high/max intensity; curated deterministic programs also run byte-for-byte equal |

On Apple hosts the e2e suite exercises the full high/max presets and VM-specific
runtime gate. On non-Apple hosts, e2e uses the portable max configuration where
backend/runtime porting is still incomplete; the IR tests still exercise the
platform-specific emitters in-process.

## Quick Use

Whole pipeline from `clang`:

```sh
clang -O2 -fpass-plugin=build/src/pipeline/libMorok.dylib \
  -mllvm -morok \
  -mllvm -morok-preset=high \
  -mllvm -morok-seed=1234 \
  prog.c -o prog
```

Whole pipeline from `opt`:

```sh
opt -load-pass-plugin build/src/pipeline/libMorok.dylib \
  -passes=morok prog.ll -o out.bc
```

One standalone pass:

```sh
opt -load-pass-plugin build/src/pipeline/libMorok.dylib \
  -passes=morok-strenc prog.ll -o out.bc
```

Configuration can be supplied by flag or environment:

```sh
clang -O2 -fpass-plugin=build/src/pipeline/libMorok.dylib \
  -mllvm -morok \
  -mllvm -morok-config=morok.toml \
  -mllvm -morok-seed=0xC0FFEE \
  prog.c -o prog

MOROK_CONFIG=morok.toml clang -O2 -fpass-plugin=... -mllvm -morok prog.c -o prog
```

Cross-build helper:

```sh
./cross_build.sh --source programs/cf_license_crackme.c --out-dir build/cross
./cross_build.sh --linux-only --source boo.c --out-dir build/cross
./cross_build.sh --macos-arches "arm64 x86_64" --preset max
```

For static Linux outputs, `cross_build.sh` derives a temporary config that
disables `function_call_obfuscate`: a fully static binary has no dynamic loader,
so a `dlsym(RTLD_DEFAULT, ...)` fallback cannot resolve imports at runtime and
adds no useful hiding surface.

## Configuration Model

Config layering is intentionally simple:

1. `[global].preset` loads `low`, `mid`, `high`, or `max`.
2. `[passes.*]` sections override only fields they mention.
3. Ordered `[[policy]]` rules can apply another preset and/or pass overrides to
   matching module/function regexes.
4. `-mllvm -morok-seed=N` overrides the config seed for deterministic builds.

Example:

```toml
[global]
preset = "high"
seed = 0xDEADBEEF1337
demangle_names = true

[passes.string_encryption]
enabled = true
probability = 100
skip_content = ["Usage:"]

[passes.function_call_obfuscate]
enabled = true

[passes.windows_process_mitigations]
enabled = true

[[policy]]
function = "^main$"
passes.bcf.enabled = false
passes.substitution.enabled = false

[[policy]]
function = "license|verify|decrypt"
passes.mba.enabled = true
passes.external_opaque_predicates.enabled = true
```

Source annotations are copied from Clang's `llvm.global.annotations` into Morok
metadata before scheduling:

```c
__attribute__((annotate("sub")))    static int force_sub(int x) { return x + 1; }
__attribute__((annotate("nosub")))  static int skip_sub(int x)  { return x + 1; }
__attribute__((annotate("sensitive"))) static int hot_secret(int x) { return x * 7; }
```

Per-function annotation keys are the scheduler tags, such as `sub`, `mba`,
`split`, `bcf`, `optamp`, `threshold`, `aliasop`, `extop`, `decoy`, `nistate`,
`entfla`, `csm`, `fla`, `stateop`, `ifsm`, `phitangle`, `typepun`,
`stackcoalesce`, `stackdelta`, `ptrlaunder`, `dfi`, `tablearith`, `uniform`,
`vobf`, `pathexplode`, `mq`, `tracekey`, `dispatchless`, `microstress`,
`selfcheck`, `mutualguard`, `shamir`, `constenc`, and `indibran`. Prefix any key
with `no` to force it off for that function.

### Presets

| Preset | Intent |
|---|---|
| `low` | Light scalar/control rewriting, string encryption, constant sharing, split blocks, and retained decoy strings. |
| `mid` | Broader scalar/control obfuscation with more density and vector/table features than `low`. |
| `high` | Bounded aggressive mode: small capped VM/self-decrypt/integrity/table/MQ/microstress/function-wrapper slices while keeping expensive graph-wide searches opt-in. |
| `max` | Full preset-managed stack: high probabilities, maximal tested budgets, anti-debug/anti-hook/timing/trap bundle, FCO, VM, self-decrypt, integrity, routing, wrappers, and decoys. |

The scheduler enforces instruction, block, function, module, byte, table, route,
callsite, clone, and payload caps. If a function or module grows beyond the
budget, later growth passes are skipped rather than allowing exponential IR
growth.

## Scheduler Order

The whole-pipeline `morok` pass is ordered to preserve semantics and maximize
composition:

```text
VM(user code)
-> hash-gated VM self-decrypt
-> anti-hook / anti-class-dump / Windows substrate and Windows probes
-> anti-debug / timing / trap / page-fault / cache / microarchitectural probes
-> decoy strings
-> string encryption
-> function-call obfuscation
-> vtable integrity
-> per-function structural, scalar, CFG, data-flow, integrity, and literal passes
-> VM/hardening for generated protection helpers
-> nanomites
-> adversarial self-tuning / merge / function wrappers
-> per-build polymorphism
-> misleading metadata
-> generated-symbol privacy cleanup
```

The precise maintained order is documented in
[`docs/algorithms.md`](docs/algorithms.md#scheduler-order-to-preserve-semantics).

## Pass Inventory

Each pass can be run standalone with `-passes=morok-*` or through the scheduler
with a TOML section. Some final hygiene transforms, such as misleading metadata
and private-linkage cleanup for generated `morok.*` helpers, are scheduler-only.

### Structural, Control-Flow, and Decompiler Stress

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Split basic blocks | `morok-split` | `split_blocks` | Splits blocks into more dispatch targets. |
| Bogus control flow | `morok-bcf` | `bcf` | Opaque-true guarded junk/decoy edges with optional entropy/junk-asm pressure. |
| Flattening | `morok-flatten` | `flattening` | Classic switch-dispatcher control-flow flattening. |
| Data-entangled flattening | `morok-entfla` | `data_entangled_flattening` | Stores successor state through live-data and previous-state tokens. |
| Non-invertible state | `morok-nistate` | `non_invertible_state` | Uses keyed lossy hashes for encoded dispatcher states. |
| Stateful opaque predicates | `morok-stateop` | `state_opaque_predicates` | Places opaque guards over flattened state plus scalar live terms. |
| Interprocedural FSM | `morok-ifsm` | `interprocedural_fsm` | Routes flattened state transitions through mutually-recursive helper calls. |
| Chaos state machine | `morok-csm` | `chaos_state_machine` | Flattens through logistic-map or T-function state evolution. |
| T-function flattening | `morok-tfa` | `chaos_state_machine` | Convenience standalone CSM variant using a single-cycle T-function generator. |
| Dispatcherless routing | `morok-dispatchless` | `dispatcherless_routing` | Replaces direct branch/switch edges with state-entangled `indirectbr` DAGs. |
| Indirect branch | `morok-indbr` | `indirect_branch` | Lowers surviving conditional/switch edges through randomized `indirectbr` tables. |
| Microcode stress | `morok-microstress` | `microcode_stress` | Emits oversized blockaddress tables and aliased decoy destinations. |
| Path explosion | `morok-pathexplode` | `path_explosion` | Adds opaque-guarded input-derived decoy loops and volatile symbolic stores. |
| Coherent decoys | `morok-decoy` | `coherent_decoys` | Adds plausible dead alternate return computations and hidden decoy-tamper state. |
| Alias opaque predicates | `morok-aliasop` | `alias_opaque_predicates` | Maintains pointer/alias invariants that guard decoy edges. |
| External opaque predicates | `morok-extop` | `external_opaque_predicates` | Uses IPO-blocked volatile helper guards and scratch decoy arms. |
| MQ gate | `morok-mq` | `mq_gate` | Plants GF(2) quadratic opaque gates over argument-derived bits. |
| Nanomites | `morok-nanomites` | `nanomites` | Replaces selected branches with trap-mediated encrypted target lookup on supported POSIX triples. |
| Adversarial merge/outline | `morok-afm` | `adversarial_function_merging` | Merges same-signature functions behind selector dispatchers and outlines scalar fragments. |
| Adversarial self-tuning | `morok-selftune` | `adversarial_self_tuning` | Scores cloned candidate bundles and replays the strongest verifier-clean bundle. |
| Per-build polymorphism | `morok-polymorph` | `per_build_polymorphism` | Reorders functions/blocks and adds neutral volatile return anchors from the seed. |

### Scalar, Data-Flow, Stack, and Literal Obfuscation

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Instruction substitution | `morok-substitution` | `substitution` | Rewrites integer ops into equivalent expression trees. |
| Mixed Boolean-Arithmetic | `morok-mba` | `mba` | Layers MBA identities and zero-noise terms. |
| Optimizer amplification | `morok-optamp` | `optimizer_amplification` | Emits input-selected equivalent forms before optimizer lowering. |
| Sub-threshold persistence | `morok-threshold` | `sub_threshold_persistence` | Adds volatile local-seed opaque-zero terms below fold thresholds. |
| Constant encryption | `morok-constenc` | `constant_encryption` | Reconstructs literals from volatile XOR shares and optional Feistel/sharing layers. |
| Shamir threshold sharing | `morok-shamir` | `shamir_share` | Reconstructs selected scalar literals from volatile GF(2^8) threshold shares. |
| Table arithmetic | `morok-tablearith` | `table_arithmetic` | Lowers narrow/const-indexed ops to encrypted lazy lookup tables. |
| Uniform primitive lowering | `morok-uniform` | `uniform_primitive_lowering` | Table-lowers byte ops and selected branches into memory-loaded dispatch. |
| Vector obfuscation | `morok-vec` | `vector_obfuscation` | Lifts scalar ops/casts/comparisons/selects into SIMD lanes. |
| Stack coalescing | `morok-stackcoalesce` | `stack_coalescing` | Collapses static allocas into one opaque byte buffer. |
| Stack delta games | `morok-stackdelta` | `stack_delta_games` | Adds dynamic stack-pointer deltas and overlapping volatile stack touches. |
| Pointer laundering | `morok-ptrlaunder` | `pointer_laundering` | Sends pointers/scalars through pointer-int and byte-vector boundaries. |
| Type punning | `morok-typepun` | `type_punning` | Round-trips scalars through volatile union-buffer reinterpretation chains. |
| PHI tangling | `morok-phitangle` | `phi_tangling` | Builds redundant scalar PHI webs and cross-edge value copies. |

### Strings, Imports, Calls, and C++ Dispatch

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| String encryption | `morok-strenc` | `string_encryption` | Encrypts eligible private byte-array globals with a unique per-string cipher. Safe C-string callsites are materialized into per-use stack buffers; unsupported uses get per-string constructor decryptors. |
| Function-call obfuscation | `morok-fco` | `function_call_obfuscate` | Hides external calls behind per-site import indirection. Linux/macOS 64-bit paths use manual export-by-hash resolvers and avoid plaintext `dlsym`; unsupported targets use per-site cloaked `dlsym`. |
| Function wrapper | `morok-funcwrap` | `function_wrapper` | Wraps calls after per-function transforms so callers see proxy edges. |
| VTable integrity | `morok-vtable` | `vtable_integrity` | Guards Itanium C++ virtual dispatches by expected vptr, slot, target, and cookie hash. |
| Decoy strings | `morok-decoystr` | `decoy_strings` | Distributes retained plaintext honeypot diagnostics and fake logging infrastructure. |

String encryption intentionally excludes generated `morok.decoy.str.*` globals.
Those decoys must remain visible to cheap triage tools such as `strings`; real
user strings are encrypted, length-padded where safe, and materialized lazily.

### Virtualization and Integrity Entanglement

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Virtualization | `morok-vm` | `virtualization` | Lifts eligible integer/pointer computation kernels to encrypted threaded bytecode VMs, including multi-block, memory, cast, compare, division, and selected intrinsic idioms. |
| Hash-gated self-decrypt | `morok-selfdecrypt` | `hash_gated_self_decrypt` | Lazily decrypts VM bytecode from runtime hashes/context and re-encrypts on helper exit. |
| Self-checksum constants | `morok-selfcheck` | `self_checksum_constants` | Fuses constants with runtime checksum diffs so tamper corrupts data instead of branching. |
| Mutual guard graph | `morok-mutualguard` | `mutual_guard_graph` | Emits overlapping checksum nodes whose aggregate diff poisons scalar returns. |
| Data-flow integrity | `morok-dfi` | `data_flow_integrity` | Decodes narrow op tables from runtime integrity hashes and decoy hidden state. |
| Execution-trace keying | `morok-tracekey` | `execution_trace_keying` | Carries a rolling trace accumulator and delayed tamper samples through data/control state. |

The scheduler runs a second, restricted VM/hardening stage over allowlisted
generated protection helpers so anti-debug, anti-hook, decryptor, and integrity
logic is not left as a simple native plaintext island.

### Anti-Analysis and Platform Runtime Passes

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| Anti-debugging | `morok-antidbg` | `anti_debugging` | Layered POSIX debugger probes, watchdog cadence, direct syscalls where supported, Linux Landlock/seccomp/memfd re-exec/DR helper paths, macOS ptrace/sysctl/csops/Mach debug-state paths, and hidden-state folding. |
| Anti-hooking | `morok-antihook` | `anti_hooking` | Clean-copy executable byte diff, prologue hook scan, function-window MACs, GOT/PLT or Mach-O fixup validation, W^X enforcement, address-space census, guarded pages, anti-dump, call-stack origin checks, method divergence, anti-VM/DBI heuristics, negative-space verification, and corroboration scoring. |
| Anti-class-dump | `morok-antiacd` | `anti_class_dump` | Scrambles Objective-C metadata when present. |
| Timing oracle | `morok-timing` | `timing_oracles` | Samples short spans with independent clocks and folds slow/divergent distributions into private state. |
| Trap oracle | `morok-trap` | `trap_oracles` | Installs temporary trap handlers and checks `int3`/`icebp`/TF or portable `SIGTRAP` delivery. |
| Page-fault/TLB oracle | `morok-pftlb` | `page_fault_oracles` | Maps protected code islands, validates fault provenance, and folds missing/extra/slow faults into state. |
| Cache-timing oracle | `morok-cachetime` | `cache_timing_oracles` | Pseudo-random pointer chase over code bytes with clock distribution checks. |
| Microarchitectural canary | `morok-microcanary` | `microarchitectural_canaries` | Samples branch-prediction/speculation side effects as low-confidence timing evidence. |
| Misleading metadata | scheduler-only | automatic | Plants retained fake local symbols, aliases, and contradictory-but-valid debug metadata, then hides generated helper symbols with private linkage. |

### Windows x86_64 Passes

The Windows passes are opt-in module passes. They share the Windows PE
foundation helpers instead of hardcoding duplicate offsets or import paths.

| Capability | `-passes` name | TOML section | Summary |
|---|---|---|---|
| PE foundation | `morok-winpe` | `windows_pe_foundation` | Emits GS-relative TEB/PEB readers, PE header/export-by-hash resolver, syscall-stub scanner, direct/indirect syscall thunks, and VEH registration substrate. |
| PEB/heap debug checks | `morok-winpeb` | `windows_peb_heap_debug` | Reads `BeingDebugged`, `NtGlobalFlag`, `ProcessHeap`, `Flags`, and `ForceFlags` directly. |
| Debug-object battery | `morok-windbgobj` | `windows_debug_object` | Resolves NT APIs by hashed export and probes debug port/object/flags plus debug-object type count. |
| Thread hide | `morok-winthide` | `windows_thread_hide` | Walks threads, applies `ThreadHideFromDebugger`, queries it back, and folds failures. |
| Anti-attach | `morok-winattach` | `windows_anti_attach` | Patches `DbgUiRemoteBreakin` and `DbgBreakPoint`, probes invalid-handle behavior, and avoids plaintext NT/API names. |
| Kernel-debugger census | `morok-winkdbg` | `windows_kernel_debugger` | Reads `SharedUserData`, queries kernel-debugger state, samples module/parent/window-class signals. |
| Direct/indirect syscalls | `morok-winsys` | `windows_syscalls` | Resolves SSNs with Hell's/Halo's/Tartarus-style stub scanning and compares direct vs recycled-gadget syscalls. |
| KnownDlls unhook | `morok-winunhook` | `windows_unhook` | Maps pristine `ntdll.dll`/`kernel32.dll` text from KnownDlls and locally refreshes hooked `.text`. |
| VEH audit | `morok-winveh` | `windows_veh_audit` | Locates/decode-candidates the internal VEH list and removes foreign handlers outside loader-known modules. |
| Process mitigations | `morok-winmitigate` | `windows_process_mitigations` | Hash-resolves `SetProcessMitigationPolicy` and opts into ACG (`ProhibitDynamicCode`) and CIG (`MicrosoftSignedOnly`) after Morok's startup text repair. |

## Platform Notes

- Linux x86_64: Morok uses inline `syscall` for sensitive anti-debug/anti-hook
  operations where syscall numbers/layouts are known. Static Linux cross-builds
  disable FCO automatically unless you provide an explicit config that says
  otherwise.
- macOS x86_64/arm64: anti-debugging uses Darwin syscalls or Mach APIs as
  appropriate; FCO's 64-bit macOS path parses Mach-O exports by hash and avoids
  plaintext `dlsym` for supported symbols.
- Windows x86_64: Windows-specific passes emit PE/PEB/TEB/export/syscall/VEH
  helpers into Windows-targeted IR. Behavioural e2e plugin loading is skipped on
  Windows hosts; coverage comes from core/config/IR tests and targeted object
  smokes.
- Unsupported triples keep conservative fallbacks or no-op for passes that need
  platform-specific context layouts.

## Static-Recovery Resistance Notes

The current string/import strategy is designed against simple static decoders:

- Real private byte-array strings do not share a global decryptor. Safe C-string
  uses get per-use stack materialization; unsupported uses get one private
  constructor per string.
- Each string has independent key material, keystream variant, ADD/XOR combine,
  and odd multiplier, all perturbed through volatile runtime state.
- Linux/macOS FCO does not need to emit symbol names for supported 64-bit
  targets; it carries hashes and resolves exports manually.
- Per-callsite cached function pointers are encoded with volatile seed/key
  material and exist as raw pointers only immediately before the indirect call.
- Decoy strings are retained and plaintext by design, so `strings` should find
  bait while real user strings remain hidden.

## Development Workflow

For a narrow pass edit, use the smallest focused tests first:

```sh
cmake --build build --target morok_ir_tests morok_config_tests morok_plugin
./build/tests/ir/morok_ir_tests
./build/tests/unit/config/morok_config_tests
```

Before merging or pushing a completed feature, run:

```sh
./run_tests.sh
git diff --check
```

When touching platform runtime emitters, add a targeted object/binary smoke that
proves the relevant names are absent from `strings` and that the emitted object
contains the expected constructor/helper shape.

## License

MIT. See [`LICENSE`](LICENSE).
