# apkinspect

`apkinspect` is a static analysis and unpacking CLI for Android APKs. It
contains focused transforms for observed packer, loader, and protector
families. It does not run an APK, emulate Android, or bypass application
signing.

The project is usable in two ways:

- `npm install -g github:throwshotputaway-cmd/apkinspect` for a direct
  repository installation that exposes the `apkinspect` command.
- `python -m pip install .` when Python packaging is preferred.

Both paths install the complete runtime command set. There are no optional
command dependency groups to select.

## Requirements

- Python 3.9 or newer, including `venv` and `pip`.
- Node.js 18 or newer when installing through npm.
- Network access during installation so npm and pip can download runtime
  packages.
- Android SDK `dexdump` is an additional external tool for `splitkey`; it is
  not bundled or invoked automatically.

npm provides the command wrapper and bootstrap process. It does not bundle a
Python interpreter, so Python must already be installed and discoverable.

## Install with npm

Install directly from the repository:

```bash
npm install --global github:throwshotputaway-cmd/apkinspect
apkinspect --help
apkinspect --version
```

This installs the repository directly and exposes the same command as a local
checkout installation.

From a checkout of this repository, the equivalent local installation is:

```bash
npm install --global .
apkinspect --help
```

For a project-local installation:

```bash
npm install
npx apkinspect --help
```

The launcher creates an isolated Python environment inside the installed
package on first use and installs `apkinspect` plus all runtime dependencies
there. It does not modify the user's global Python environment.

If the Python executable is not on `PATH`, set `APKINSPECT_PYTHON` before
running `apkinspect`. For example, in PowerShell:

```powershell
$env:APKINSPECT_PYTHON = 'C:\Python312\python.exe'
apkinspect --help
```

On macOS and Linux, use the equivalent environment variable:

```bash
APKINSPECT_PYTHON=/path/to/python3 apkinspect --help
```

`APKINSPECT_VENV` can be set when a different private environment directory is
needed. The default is `.apkinspect-venv` inside the installed npm package.

The launcher checks for its private environment on first use and runs the
Python bootstrap automatically. There is no npm lifecycle hook, so installing
directly from GitHub does not require npm script-policy exceptions. The first
`apkinspect` command may take longer while Python dependencies are installed.

## Install with Python

Install every runtime dependency and the command entry point directly:

```bash
python -m pip install .
apkinspect --help
```

From a checkout, an editable installation is useful for development:

```bash
python -m pip install -e .
```

The legacy requirements file is also a complete runtime installation:

```bash
python -m pip install -r requirements.txt
```

Contributor tools are separate from runtime command dependencies:

```bash
python -m pip install -e ".[dev]"
```

## Runtime dependencies

Every normal installation includes:

| Package | Used by |
|---|---|
| `cryptography` | AES, HMAC, and GCM/CBC/CTR transforms |
| `androguard` | `dpt` DEX parsing and method mapping |
| `lief` | `elforacle` ELF parsing |
| `capstone` | `elforacle` x86-64 disassembly |
| `rich` | terminal status and progress rendering |

`dexdump` remains an external prerequisite for creating the input consumed by
`splitkey`. No other Android build tools are required by the commands below.

## Basic usage

```text
apkinspect <command> [options]
apkinspect --version
apkinspect --help
apkinspect <command> --help
```

The equivalent Python-module form is useful in a source checkout:

```text
python -m apkinspect <command> [options]
```

Common options may appear before or after the command:

```text
apkinspect --no-color <command> [options]
apkinspect --quiet <command> [options]
apkinspect --progress auto|always|never <command> [options]
```

- `--no-color` disables ANSI colors. `NO_COLOR` has the same effect.
- `--quiet`/`-q` suppresses status and progress messages.
- `--progress auto` enables progress on an interactive terminal.
- `--progress always` forces progress/status output even when redirected.
- `--progress never` disables progress rendering for automation.
- Status and progress go to stderr. Command result reports go to stdout, so
  `--quiet` does not remove those result lines.

Successful commands return exit code `0`. Invalid or foreign input returns
`1` with a concise error. An interrupted command returns `130`.

Output files are written atomically. ZIP verification checks ZIP structure and
entry integrity; it does not validate an Android manifest or APK signatures.
`--expect dex` checks the DEX magic, while `auto` recognizes ZIP or DEX output.

## Command index

| Command | Purpose |
|---|---|
| `lcg` | Decrypt an LCG stream-cipher `.dat` blob |
| `upd` | Decrypt an `update.enc` repeating-XOR carrier |
| `shard` | Decrypt a repeating-XOR staged asset |
| `spk` | Unwrap an SPK XOR/DEFLATE blob |
| `staged` | Reassemble, decrypt, hash-check, and inflate staged parts |
| `fogky` | Decrypt XOR/RC4x4/AES-GCM assets and containers |
| `signed` | Recover the two signed-family stages |
| `oracle` | Decode numeric DEX string-oracle call sites |
| `splitkey` | Reconstruct split-array keys from `dexdump` output |
| `elforacle` | Extract indexed XOR strings from an x86-64 `.so` |
| `midctr` | Decrypt mid-counter AES-CTR assets |
| `cloak` | Unwrap multi-layer AES-GCM/LCG/HKDF assets |
| `aes-gcm-hkdf` | Decrypt direct salt/nonce AES-GCM/HKDF assets |
| `chunked-aes-gzip` | Reassemble and decrypt numbered AES-CBC/gzip chunks |
| `xor-gzip` | Decrypt repeating-XOR plus gzip assets |
| `dpt` | Restore dpt-shell method bodies statically |
| `axml-trim` | Rebuild an APK with a trimmed binary manifest |

## Command reference

### `lcg`

Decrypts a standalone encrypted `.dat` blob using a linear congruential
stream. Extract the blob from the carrier APK before running this command;
the command does not open an APK itself.

```text
apkinspect lcg INPUT -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `INPUT` | required | Standalone encrypted file |
| `-o, --output` | required | Plaintext output path |
| `--seed` | `0x4394D` | Initial LCG state; accepts base-0 integer syntax |
| `--header` | `16` | Bytes skipped before decryption |
| `--no-verify` | off | Allow output that is not a valid ZIP |

The command applies the LCG update and XORs the high state byte with each
payload byte. A nonstandard prefix emits a warning but does not stop
processing. Verification is enabled by default, so the normal result should
be a healthy ZIP/APK; use `--no-verify` only for an intermediate blob.

### `upd`

Decrypts the conventional `assets/update.enc` carrier with a repeating XOR
key. This is usually the first layer around an inner APK.

```text
apkinspect upd APK -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `-o, --output` | required | Decrypted output path |
| `--asset` | `assets/update.enc` | Asset path inside the APK |
| `--key` | family default | Literal UTF-8 repeating-XOR key |
| `--no-verify` | off | Allow output that is not a valid ZIP |

The key is text, not hex. Pass a sample-specific key with `--key` when the
carrier does not use the family default. Output is verified as a ZIP unless
verification is disabled.

### `shard`

Decrypts one asset in a repeating-XOR staged family. The stream offset lets
multiple shards be decrypted as one logical byte stream.

```text
apkinspect shard APK ASSET -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `ASSET` | required | Asset path inside the APK |
| `-o, --output` | required | Output path |
| `--key` | family default | Literal UTF-8 repeating-XOR key |
| `--offset` | `0` | Initial stream offset |
| `--no-verify` | off | Allow output that is not a valid ZIP |

The byte at position `i` is XORed with `key[(i + offset) % len(key)]`. Use
the same key and an increasing offset when reconstructing a multi-shard
chain.

### `spk`

Unwraps the SPK carrier format. It selects an encrypted `.bin` asset,
repeating-XOR decrypts it, verifies the `SPKZ` wrapper, inflates the DEFLATE
stream, verifies the inner `SPK1` marker, and writes the inflated body.

```text
apkinspect spk APK -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `-o, --output` | required | Inflated SPK body |
| `--asset` | largest `assets/*.bin` | Exact asset to process |
| `--key` | family default | Literal UTF-8 XOR key |

The command validates the complete DEFLATE stream and does not accept
trailing bytes. It writes the `SPK1` body; it does not automatically extract
a nested shell ZIP or DEX from that body.

### `staged`

Reassembles metadata-described encrypted parts, decrypts each part with
AES-CBC, checks compressed and original SHA-256 hashes, inflates the result,
and verifies the final ZIP.

```text
apkinspect staged APK -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `-o, --output` | required | Inflated inner APK/ZIP |
| `--password` | family default | Password used to derive the AES key |
| `--asset-dir` | `assets/packed` | Directory containing parts and metadata |
| `--meta` | `meta.json` | Metadata filename inside `--asset-dir` |

Metadata is a JSON object with a `files` list. Every file entry must contain
`file`, `compressedSha256`, and `originalSha256`. Parts are decrypted strictly
in list order. Each part supplies its first 16 bytes as its IV; the AES key
is derived from the password. Wrong ordering, hashes, padding, compression,
or ZIP data fails before the output is replaced.

### `fogky`

Decrypts the Fogky-style layered asset: an XOR pad, four RC4 KSA passes, and
AES-GCM. It also understands `MSZ1` containers containing named records.

```text
apkinspect fogky APK ASSET -o OUTPUT [--key HEX] [--raw]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `ASSET` | required | Encrypted asset path |
| `-o, --output` | required | File, or directory for `MSZ1` |
| `--key` | family default | 16-, 24-, or 32-byte AES-GCM key as hex |
| `--raw` | off | Write decrypted bytes without unpacking `MSZ1` |

For an `MSZ1` container, the output must be a directory. Entry names are
flattened to safe basenames, duplicate names are rejected, and each record is
written separately. For non-container plaintext or `--raw`, the output is a
single file. ZIP-looking records are tested diagnostically but are still
written if they are not a valid ZIP.

### `signed`

Recovers the two-stage signed-family payload. Stage 1 is repeating-XOR
encrypted and checked for `dex\n`; stage 2 is AES-CBC encrypted with a key
derived from the stage-2 asset name and is checked as a ZIP.

```text
apkinspect signed APK [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `--outdir` | `.` | Directory for `stage1.dex` and `stage2.zip` |
| `--stage1` | family path | Stage-1 asset path |
| `--stage2` | family path | Stage-2 asset path |
| `--xor-key` | family default | Literal UTF-8 stage-1 XOR key |

This command handles the two configured family assets only. It writes
`stage1.dex` before attempting stage 2, so a later failure can leave a
partial output directory. It does not extract the classes inside the final
ZIP or rebuild an APK.

### `oracle`

Scans a standalone `classes.dex` for numeric string-oracle call sites. It
finds seeds associated with the selected method, applies the supported
signed-family decoder, and reports readable results.

```text
apkinspect oracle CLASSES.DEX [options]
```

| Option | Default | Meaning |
|---|---|---|
| `CLASSES.DEX` | required | Extracted DEX file, not an APK |
| `--method` | family method name | Exact oracle method name |
| `--min-score` | `0.0` | Minimum readability score to report |
| `-o, --output` | stdout | Optional UTF-8 result file |

The scanner is pattern-based rather than a complete Dalvik disassembler. It
uses the longest DEX string as the encoded blob and deduplicates seeds in
file order. If the output file is requested but no result matches, the file
is still created.

### `splitkey`

Reconstructs a key assembled from separate `const` and `aput-byte` writes in
`dexdump -d` output.

```text
apkinspect splitkey DEXDUMP_DUMP --class SUBSTRING --method METHOD [options]
```

| Option | Default | Meaning |
|---|---|---|
| `DEXDUMP_DUMP` | required | Text output from Android SDK `dexdump -d` |
| `--class` | required | Class descriptor substring |
| `--method` | required | Key-builder method name |
| `--size` | `32` | Key length in bytes |
| `-o, --output` | none | Optional raw key file |

The command always prints the recovered key as hex. Supplying `-o` also
writes the raw key bytes. Generate the input separately, for example:

```bash
dexdump -d classes.dex > classes.dump.txt
apkinspect splitkey classes.dump.txt --class MainActivity --method keyBuilder -o key.bin
```

This is a focused text parser, not general Dalvik data-flow analysis.

### `elforacle`

Extracts indexed repeating-XOR strings from a protector native library. It
targets the x86-64 ELF64 little-endian slice, locates the JNI oracle jump
table, walks its setup instructions, and writes decoded strings.

```text
apkinspect elforacle SOFILE -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `SOFILE` | required | Native ELF `.so` file |
| `-o, --output` | required | UTF-8 decoded-string output |
| `--func` | `getNativeStr` | Dynamic-symbol substring to match |
| `--bound` | auto | Maximum string index; auto-read from a comparison |
| `--default-keylen` | `12` | Fallback key length in bytes |

The library must retain usable section headers plus `.text` and `.rodata`.
The command tries mirrored data/key register conventions and keeps the more
readable result. Unsupported dynamic patterns are reported as undecoded
entries instead of being silently presented as recovered text.

### `midctr`

Decrypts a nonstandard mid-counter AES-CTR asset. The command can accept a
hex key or read 16 raw key bytes directly from a native library at a literal
file offset.

```text
apkinspect midctr APK -o OUTPUT (--key HEX | --so FILE) [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `-o, --output` | required | Decrypted output |
| `--asset` | family path | Encrypted asset path |
| `--key` | — | 16-byte AES key as hex |
| `--so` | — | Native file containing the 16 key bytes |
| `--key-off` | `0x17440` | Literal file offset used with `--so` |
| `--const` | family constant | Eight-byte counter constant |
| `--no-verify` | off | Allow output that is not a valid ZIP |

`--key` and `--so` are mutually exclusive. `--key-off` is not an ELF virtual
address; use the actual file offset. The default verification expects a ZIP,
although it does not enforce Android-specific APK contents.

### `cloak`

Unwraps the multi-stage cloak payload: AES-GCM, an inverse seeded LCG
permutation, nibble transformation, a SHA-256 counter stream, and a final
HMAC-derived AES-GCM layer.

```text
apkinspect cloak APK -o OUTPUT [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `-o, --output` | required | Decrypted output |
| `--asset` | family path | Outer encrypted asset |
| `--hk` | family default | Master key for the index stage |
| `--pk` | family default | Master key for the APK stage |
| `--kind` | try P then H | `H`, `P`, or an integer kind byte |
| `--expect` | `auto` | `auto`, `apk`, or `dex` output validation |

When `--kind` is omitted, the command tries the configured HK/PK combinations.
The first plaintext byte is a flag; odd flags trigger gzip or DEFLATE
inflation. `apk` fully validates a ZIP, `dex` checks DEX magic, and `auto`
recognizes either common output shape. Use sample-specific keys when the
family defaults do not match.

### `aes-gcm-hkdf`

Decrypts a direct salt/nonce AES-GCM blob using an HMAC-SHA256-derived key.
The key text is an obfuscated hex representation: its first byte is a prefix
used to decode the remaining hex bytes.

```text
apkinspect aes-gcm-hkdf APK ASSET -o OUTPUT (--hk TEXT | --hk-file FILE) [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `ASSET` | required | Encrypted asset path |
| `-o, --output` | required | Output file |
| `--hk` | — | Obfuscated key text as ASCII hex |
| `--hk-file` | — | File containing the obfuscated key text |
| `--kind` | `H` | `H`, `P`, or an integer kind byte |
| `--expect` | `dex` | `auto`, `apk`, or `dex` output validation |

The blob layout is a 16-byte salt, 12-byte nonce, and AES-GCM ciphertext/tag.
The derived key uses `HMAC-SHA256(salt, key)` followed by
`HMAC-SHA256(PRK, kind || 0x01)`, with `salt + kind` as AAD. The first
plaintext byte is a compression flag and is removed. Use `--hk-file` for
recovered material instead of putting it in shell history.

### `chunked-aes-gzip`

Reads a numbered sequence of APK assets, concatenates them, XORs the combined
stream with `SHA-256(key)`, decrypts AES-CBC, removes PKCS#7 padding, and
inflates gzip.

```text
apkinspect chunked-aes-gzip APK -o OUTPUT (--key HEX | --key-file FILE) [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `-o, --output` | required | Inflated payload |
| `--key` | — | 16-, 24-, or 32-byte AES key as hex |
| `--key-file` | — | File containing the AES key hex |
| `--prefix` | `assets/vbfk/iyxu_` | Chunk path prefix |
| `--suffix` | `.png` | Chunk path suffix |
| `--start` | `0` | First decimal chunk index |
| `--count` | `10` | Number of consecutive chunks |
| `--expect` | `apk` | `auto`, `apk`, or `dex` output validation |

Chunk names are exactly `<prefix><start+i><suffix>` with ordinary decimal
indices. The default `apk` expectation fully validates the inflated ZIP but
does not check Android-specific manifest or signature content.

### `xor-gzip`

Decrypts an asset with a repeating XOR key and then requires standard gzip
compression.

```text
apkinspect xor-gzip APK [ASSET] -o OUTPUT (--key HEX | --key-file FILE) [options]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Carrier APK |
| `ASSET` | `assets/f89710c8` | Encrypted asset path |
| `-o, --output` | required | Inflated output |
| `--key` | — | Repeating-XOR key as hex |
| `--key-file` | — | File containing the key hex |
| `--expect` | `dex` | `auto`, `apk`, or `dex` output validation |

Any nonempty decoded key length is accepted. Raw zlib without a gzip wrapper
is rejected. Use `auto` when the same transform can produce either a ZIP or
DEX, or `apk` when the result must be a structurally valid ZIP.

### `dpt`

Statically restores method bodies from a dpt-shell packed APK. It reads the
configured bytecode store, extracts DEX files appended to the stub
`classes.dex`, matches method indexes to code capacity, patches instruction
bytes, and repairs DEX SHA-1/Adler-32 headers.

```text
apkinspect dpt APK [-o OUTDIR] [--oooo ASSET]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Packed APK |
| `-o, --outdir` | `unpacked` | Directory for restored `classes*.dex` |
| `--oooo` | `assets/OoooooOooo` | Bytecode-store asset |

Both standard records and the size-first XOR-`0x6f` variant are supported.
Sections must map exactly to a DEX by complete code-capacity fit. The output
is a directory of DEX files, not a signed APK.

### `axml-trim`

Rebuilds an APK after truncating a binary `AndroidManifest.xml` immediately
after its first `END_NAMESPACE` chunk. This can remove filler chunks that
confuse some parsers.

```text
apkinspect axml-trim APK -o OUTPUT [--entry AndroidManifest.xml]
```

| Option | Default | Meaning |
|---|---|---|
| `APK` | required | Input APK |
| `-o, --output` | required | Rebuilt APK path |
| `--entry` | `AndroidManifest.xml` | Binary manifest entry to trim |

The input entry must begin with binary AXML magic. The command rebuilds a
ZIP and does not preserve arbitrary ZIP metadata or APK v2/v3 signing blocks.
Resign the output before attempting to install it on a device.

## Output and safety behavior

- Output files are written to a temporary sibling and atomically replaced.
- Archive-derived paths are checked for traversal, absolute paths, and unsafe
  names before extraction.
- ZIP output is tested with `zipfile.testzip()` unless a command explicitly
  disables verification.
- Empty ZIP containers are accepted as valid ZIPs.
- `apk`/`zip` means ZIP validation, not Android manifest or signature
  validation.
- `dex` checks the `dex\n` magic; `auto` recognizes ZIP or DEX magic.
- Recovered keys and decrypted payloads should be treated as sensitive. Prefer
  key files, avoid shell history, and do not commit sample material.
- `axml-trim` and `dpt` do not produce an installable signed APK; signing,
  rebuilding, and device installation remain separate steps.

## Development

Run the Python test suite and static checks from a checkout:

```bash
python -m unittest discover -s tests -v
python -m compileall -q apkinspect tests
python -m ruff check .
python -m mypy
python -m build
```

Validate the npm package:

```bash
npm install
npm pack --dry-run
```

To exercise the complete first-run path, use a disposable environment with
Python and network access, then run `apkinspect --version` after installation.
