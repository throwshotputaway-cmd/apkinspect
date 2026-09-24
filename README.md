# apkinspect

Static decryptors and unpackers for packed Android APKs, exposed as one
installable Python CLI. Each subcommand targets a builder or packer line
observed in the wild.

## Install

For the core CLI:

```bash
python -m pip install -e .
```

Install optional command dependencies when needed:

```bash
python -m pip install -e ".[dpt]"
python -m pip install -e ".[elf]"
python -m pip install -e ".[ui]"
python -m pip install -e ".[all]"
```

The legacy dependency file installs the project with all optional commands:

```bash
python -m pip install -r requirements.txt
```

Python 3.9 or newer is required. The core package needs `cryptography`.
`dpt` needs `androguard`; `elforacle` needs `lief` and `capstone`.
`rich` enables the polished terminal UI; without it, the CLI uses a plain
TTY fallback.

## Usage

```text
apkinspect <command> [options]
python -m apkinspect <command> [options]
apkinspect --version
apkinspect --help
apkinspect --no-color <command> [options]
apkinspect --quiet <command> [options]
apkinspect --progress always <command> [options]
```

Status and progress output go to stderr, so stdout remains usable for
command results. Use `--progress never` for fully quiet automation.

## Commands

| command | purpose |
|---|---|
| `lcg` | LCG stream-cipher `.dat` dropper payloads |
| `upd` | repeating-XOR `assets/update.enc` carriers |
| `shard` | repeating-XOR single-blob `.raw` assets |
| `spk` | SPK-line `.bin` blobs with XOR and DEFLATE layers |
| `staged` | hash-verified, `meta.json`-driven AES-CBC payloads |
| `fogky` | XOR-pad, RC4x4 and AES-GCM blobs; extracts `MSZ1`/`MSP1` split sets |
| `signed` | two-stage dictionary-name assets |
| `oracle` | numeric DEX string-oracle call sites |
| `splitkey` | split-array AES keys from `dexdump -d` output |
| `elforacle` | indexed XOR string tables in x86_64 `.so` files |
| `midctr` | nonstandard mid-counter AES-CTR assets |
| `cloak` | multi-layer AES-GCM, LCG and HKDF-GCM assets |
| `aes-gcm-hkdf` | direct AES-GCM/HKDF loader assets |
| `chunked-aes-gzip` | numbered chunk, SHA-256-XOR, AES-CBC and gzip assets |
| `xor-gzip` | repeating-XOR plus gzip assets |
| `dpt` | static dpt-shell method restoration |
| `axml-trim` | rebuild an APK with a filler-trimmed binary manifest |

Commands emit concise errors for invalid input and return non-zero status
without a traceback. Output files are written atomically. Archive-derived
output names are checked before extraction, and empty ZIPs are accepted as
valid ZIP containers.

`--no-verify` is available on `lcg`, `upd`, `shard` and `midctr` when the
caller intentionally wants to inspect a non-ZIP intermediate result.

## Examples

```bash
apkinspect upd carrier.apk -o payload.apk
apkinspect lcg blob.dat -o payload.apk --seed 0x4394D --header 16
apkinspect dpt packed.apk -o unpacked/
apkinspect fogky carrier.apk assets/blob -o out.bin --key 00112233445566778899aabbccddeeff
apkinspect fogky carrier.apk assets/dnshz4t -o split_set --key 00112233445566778899aabbccddeeff
apkinspect oracle classes.dex --method q2sx0mC159653E9dHg -o strings.txt
apkinspect splitkey dump.txt --class MainActivity --method abm4 -o key.bin
apkinspect elforacle lib/x86_64/libfoo.so -o strings.txt
apkinspect axml-trim carrier.apk -o trimmed.apk
apkinspect aes-gcm-hkdf carrier.apk assets/payload -o stage2.dex --hk-file aes-gcm.key
apkinspect chunked-aes-gzip carrier.apk -o payload.apk --key-file chunks.key --count 10
apkinspect xor-gzip payload.apk assets/payload -o payload.dex --key-file xor.key
```

Use an installed `apkinspect` command after installation. The equivalent
`python -m apkinspect` form is useful from a source checkout.

## Research notes

- `dexdump` is an external Android SDK tool required by `splitkey`.
- `aes-gcm-hkdf`, `chunked-aes-gzip` and `xor-gzip` require a per-sample key;
  use `--key-file` or `--hk-file` instead of putting recovered keys in shell
  history or logs.
- These three commands are static transforms and do not require an Android
  runtime.
- `elforacle` currently targets the x86_64 ELF64 little-endian slice.
- `axml-trim` creates a new ZIP and does not preserve APK v2/v3 signing
  blocks; resign the output before installing it on a device.
- `dpt` writes restored `classes*.dex` files and does not rebuild a signed
  APK.
- Default keys, seeds and passwords are family constants. Override them per
  sample with the command-specific options and treat extracted material as
  sensitive.
- Do not test with other people's accounts. Use Meta or carrier-provided test
  accounts when the program requires them.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q apkinspect tests
python -m ruff check .
python -m mypy
python -m pip install -e ".[all,dev]"
python -m build
```

The integration tests use local APK fixtures and skip when their configured
fixture is absent. Override the defaults with `APKINSPECT_TEST_APK`,
`APKINSPECT_TEST_CLOAK_APK` and `APKINSPECT_FOGKY_APK` when running against a
different sample set.
