# KindleGoodnotes

Reverse-engineered Goodnotes (`.goodnotes`, `schema_version = 35`) binary format specification, Protocol Buffers schema, and zero-dependency Python 3 codec.

## Contents

- [`GOODNOTES_FORMAT_SPEC.md`](GOODNOTES_FORMAT_SPEC.md) — Format specification covering ZIP layout, delimited protobuf framing, Apple `bv41`/`bv4-` LZ4 blocks, `tpl\x00` stroke serialization, CRDT events, and writing guidelines.
- [`proto/goodnotes.proto`](proto/goodnotes.proto) — `proto3` message definitions for `.goodnotes` streams.
- [`tools/goodnotes_codec.py`](tools/goodnotes_codec.py) — Standard-library-only Python 3 disassembler, SVG preview renderer, programmatic `GoodnotesBuilder` writer, and round-trip verifier.

## Usage

```sh
python3 tools/goodnotes_codec.py verify <archive.goodnotes>
python3 tools/goodnotes_codec.py disassemble <archive.goodnotes> <output_dir>
python3 tools/goodnotes_codec.py render-svg <archive.goodnotes> <output_dir>
python3 tools/goodnotes_codec.py create-sample <output.goodnotes>
```

> **Note:** Local `.goodnotes` specimen archives and `disassembled/` inspection outputs are `.gitignore`d.
