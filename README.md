# apkinspect

Static decryptors and unpackers for packed / trojanized Android APKs, as a
single CLI. Each subcommand targets one builder/packer line observed in the
wild (XOR droppers, AES staged payloads, string oracles, dpt-shell, …).

```
python -m apkinspect <command> [options]
```

## Install

```bash
pip install -r requirements.txt
```

Requires Python 3.9+. Per-command extras: `dpt` needs `androguard`,
`elforacle` needs `lief` + `capstone`; everything else needs only
`cryptography` (AES) plus the standard library.

## Commands

| command     | what it does |
|-------------|--------------|
| `lcg`       | LCG stream-cipher `.dat` dropper payloads (`SEED`/`--header` tunable) |
| `upd`       | repeating-XOR `update.enc` carriers (builder key default) |
| `shard`     | repeating-XOR single-blob staged `.raw` assets (`--offset` for chains) |
| `spk`       | SPK-line `.bin` blobs: XOR outer layer + `SPKZ`/DEFLATE inner layer |
| `staged`    | `meta.json`-driven multi-part AES-CBC payloads, hash-verified, gunzipped |
| `fogky`     | XOR-pad → RC4 (x4 KSA) → AES-GCM blobs |
| `signed`    | two-stage dictionary-name assets (XOR DEX loader, then AES-CBC asset ZIP) |
| `oracle`    | decode numeric string-oracle (`const-wide` seed) call sites in a DEX |
| `splitkey`  | split-array AES keys from `dexdump -d` output (`const/16` + `aput-byte`) |
| `elforacle` | indexed XOR string tables in protector `.so` files (x86_64) |
| `icici-ctr` | mid-counter AES-CTR assets (counter in block bytes 8–11, not stock CTR) |
| `sbi`       | SBI-line assets: AES-GCM unshell → LCG un-permute/nibble/keystream → HKDF-GCM |
| `dpt`       | statically unpack dpt-shell APKs (restores hollowed method bodies) |
| `axml-trim` | rebuild APK with filler-trimmed `AndroidManifest.xml` (fixes jadx/apktool) |

Every command fails with a one-line `ERROR: …` (exit 1) instead of a
traceback when the input is from a different builder line, and verifies
output (ZIP test / magic / GCM tag) by default (`--no-verify` to skip).

## Examples

```bash
# update.enc line: XOR-decrypt and verify the inner ZIP
python -m apkinspect upd carrier.apk -o payload.apk

# LCG .dat dropper with a non-default seed
python -m apkinspect lcg blob.dat -o payload.apk --seed 0x4394D --header 16

# dpt-shell: restore hollowed methods, fixed DEX headers to unpacked/
python -m apkinspect dpt packed.apk -o unpacked/

# ICICI line: key straight from the native lib's .data section
python -m apkinspect icici-ctr carrier.apk -o inner.apk \
    --so libhhcbcu.so --key-off 0x17440 --const 0x6b71def9b8938f83

# numeric string oracle in a DEX
python -m apkinspect oracle classes.dex --method q2sx0mC159653E9dHg -o strings.txt

# split-array key from dexdump output, then fogky blob with that key
dexdump -d classes.dex > dump.txt
python -m apkinspect splitkey dump.txt --class MainActivity --method abm4 -o key.bin
python -m apkinspect fogky carrier.apk assets/blob -o out.bin --key $(xxd -p key.bin | tr -d '\n')

# native string table from a protector .so (x86_64)
python -m apkinspect elforacle lib/arm64-v8a/libfoo.so -o strings.txt
```

## Effectiveness check

`tests/test_union.py` exercises the CLI against `union.apk`, an
`update.enc`-line carrier (not shipped here — set `APKINSPECT_TEST_APK`
or pass `--apk`):

```bash
python -m unittest discover -s tests
```

Expected: `upd` recovers a valid inner ZIP; the line-specific commands
(`signed`, `icici-ctr`, `dpt`, `oracle`, `lcg`) exit non-zero with clean
one-line errors instead of tracebacks.

## Notes

- No samples, keys beyond builder defaults, or victim data are included.
- Builder defaults (XOR keys, seeds, passwords) are per-family constants
  recovered from disassembly; override them per sample via CLI flags.
- `dpt` handles the standard and size-first-XOR-`0x6f` `OoooooOooo`
  variants and resolves bytecode sections to DEX files by exact
  code-capacity fit.
