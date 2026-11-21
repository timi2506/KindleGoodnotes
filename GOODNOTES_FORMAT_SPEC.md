# Goodnotes `.goodnotes` Binary Format Specification

**Reverse-Engineered & Byte-Verified Specification (`schema_version = 35`)**  
**Source Specimen:** [`Test.goodnotes`](Test.goodnotes) (3,506,781 bytes, 27 ZIP entries)  
**Companion Code & Artifacts:**
- [`goodnotes_codec.py`](tools/goodnotes_codec.py) — Reference zero-dependency Python 3 reader, disassembler, SVG renderer, programmatic writer (`GoodnotesBuilder`), and round-trip verifier.
- [`goodnotes.proto`](proto/goodnotes.proto) — Complete `proto3` message definitions (82 messages).
- [`disassembled/raw/`](disassembled/raw) — Exact unzipped files from `Test.goodnotes`.
- [`disassembled/decoded/`](disassembled/decoded) — Decoded JSON dumps for all binary files.
- [`disassembled/previews/`](disassembled/previews) — Reconstructed SVG renders (`page_1_cover.svg`, `page_2_tools.svg`, `page_3_dotted.svg`).

---

## 1. Overview & ZIP Container Layout

A `.goodnotes` file (modern Goodnotes 6+ CRDT/event-sourced format, `schema.pb` version 24–35) is a **standard ZIP archive** using DEFLATE compression (method `8`).

Every archive contains:
- **`schema.pb`** — Minimum compatible reader version (`max(min_schema_version)` across all objects in the archive).
- **`document.info.pb`** — 0-byte empty file in modern archives (document metadata lives in `index.events.pb`).
- **`index.events.pb`** — Append-ordered CRDT event log defining the document, attachments, templates, pages, active page cursor, and search-indexing history.
- **`index.notes.pb`** — Index mapping each `NoteLayerUUID` to `notes/<NoteLayerUUID>`.
- **`index.attachments.pb`** — Index mapping each `LogicalAttachmentUUID` to `attachments/<StorageBlobUUID>`.
- **`index.search.pb`** — Index mapping page `NoteLayerUUID`s and PDF `AttachmentUUID`s to `search/<UUID>`.
- **`notes/<NoteLayerUUID>`** — Per-page binary stream of paired `[NoteObjectHeader, NoteObjectPayload]` records.
- **`search/<UUID>`** — Handwritten/typed search index (`PageSearchIndex`) or extracted PDF page text (`PdfSearchPage` stream).
- **`attachments/<StorageBlobUUID>`** — Raw template PDFs, imported PDFs, PNGs, and JPEGs.
- **`thumbnail.jpg`** — Cover preview JPEG (353×499 in `Test.goodnotes`).

### 1.1 Complete File Manifest of `Test.goodnotes` (27 Files)

| Archive Path | Uncompressed Size | Framing / Media Format | Role |
|---|---:|---|---|
| `schema.pb` | 2 B | Raw single protobuf (`SchemaVersion`) | Stores `schema_version = 35` (`08 23`) |
| `document.info.pb` | 0 B | Empty | Reserved/legacy metadata placeholder |
| `thumbnail.jpg` | 6,215 B | JPEG (353×499) | Document cover preview thumbnail |
| `index.events.pb` | 18,007 B | Delimited protobuf stream (77 msgs) | Document, attachment, template, page, & search event log |
| `index.notes.pb` | 332 B | Delimited protobuf stream (4 msgs) | Maps 4 `NoteLayerUUID`s → `notes/<UUID>` |
| `index.attachments.pb` | 890 B | Delimited protobuf stream (10 msgs) | Maps 10 `LogicalAttachmentUUID`s → `attachments/<BlobUUID>` |
| `index.search.pb` | 510 B | Delimited protobuf stream (6 msgs) | Maps 3 note layers (`kind=0`) + 3 PDFs (`kind=1`) → `search/<UUID>` |
| `notes/23B4A80F-6A3A-40D9-A587-1CFB895B6A39` | 503 B | Delimited protobuf stream (4 msgs / 2 objs) | Page 1 (Blue Cover): 1 active Ballpoint dot + 1 tombstoned stroke |
| `notes/9AFA8DE4-2C4A-400D-B88F-C32043C9ED9F` | 137,528 B | Delimited protobuf stream (282 msgs / 141 objs) | Page 2 (Black Ruled): 126 active + 15 deleted objects (all tools) |
| `notes/45ACB5BF-26A6-47E8-B407-584D5408ADB2` | 32,027 B | Delimited protobuf stream (60 msgs / 30 objs) | Page 3 (White Dotted): 28 active + 2 deleted Fountain strokes |
| `notes/EE6C27D0-0C00-574B-8943-1650E68D2BC1` | 0 B | Empty | Page 4 (Scanned PDF): no user annotations on note layer |
| `search/23B4A80F-6A3A-40D9-A587-1CFB895B6A39` | 365 B | Raw single protobuf (`PageSearchIndex`) | Page 1 HWR search index (1 stroke candidate) |
| `search/9AFA8DE4-2C4A-400D-B88F-C32043C9ED9F` | 44,655 B | Raw single protobuf (`PageSearchIndex`) | Page 2 HWR (39 word candidates) + 5 typed-text slots |
| `search/45ACB5BF-26A6-47E8-B407-584D5408ADB2` | 10,365 B | Raw single protobuf (`PageSearchIndex`) | Page 3 HWR (5 candidates: `Hi`, `different`, `template`) |
| `search/C3BDD217-2DBE-446F-93AA-627A50476403` | 5 B | Delimited stream (`04 10 01 1a 00`) | Page 1 Cover PDF search (`page=1, text=""`) |
| `search/D08775A5-BFFF-43DF-BB1C-342328C3BCDD` | 5 B | Delimited stream (`04 10 01 1a 00`) | Page 2 Black Ruled PDF search (`page=1, text=""`) |
| `search/8DF7E563-FDD1-4B3D-9F19-0184993B3B0E` | 5 B | Delimited stream (`04 10 01 1a 00`) | Page 3 White Dotted PDF search (`page=1, text=""`) |
| `attachments/C3BDD217-2DBE-446F-93AA-627A50476403` | 1,369 B | `%PDF-1.7` (`svg2pdf`, 595.28×841.89 pt) | Blue Cover template PDF |
| `attachments/D08775A5-BFFF-43DF-BB1C-342328C3BCDD` | 1,836 B | `%PDF-1.7` (`svg2pdf`, 595.28×841.89 pt) | Black Ruled template PDF |
| `attachments/8DF7E563-FDD1-4B3D-9F19-0184993B3B0E` | 77,505 B | `%PDF-1.7` (`svg2pdf`, 595.28×841.89 pt) | White Dotted template PDF |
| `attachments/389FABA8-B298-4F6B-8CB1-8939C20F94EA` | 1,008,164 B | `%PDF-1.3` (iOS Quartz, 612×792 pt) | Page 4 scanned JPEG + invisible `3 Tr` OCR text layer (logical ID `EED94C43-...`) |
| `attachments/D62A8C11-7D30-4FD0-870B-046700629301` | 1,292,098 B | PNG (1255×998 RGBA) | Page 2 embedded photo (`2814BC74-...`) |
| `attachments/E745B161-3417-4F5F-AFA0-0FF40BAEE26D` | 192,169 B | JPEG (1179×1363) | Page 2 Sticker/Element (`B1F57681-...`) |
| `attachments/A438C528-1692-4AE3-A881-9757C503F8C3` | 36,333 B | PNG (712×712 RGBA) | Page 2 Math Assist Graph render (`FE157E62-...`) |
| `attachments/04284602-F50E-4834-93C9-51CDAB1D4ACC` | 808,932 B | JPEG (1908×2746) | Orphaned historical attachment (registered in `index.events.pb` & `index.attachments.pb`, unused by active elements) |
| `attachments/D14CA816-E570-4DCE-B450-CC0F8659AD7B` | 38,123 B | PNG (704×704 RGBA) | Orphaned historical Math Assist graph render |
| `attachments/0F273E2C-10C3-4641-B58B-0F3EDC595F76` | 37,875 B | PNG (708×708 RGBA) | Orphaned historical Math Assist graph render |

### 1.2 Framing Rule (Critical!)

Do **not** assume all `.pb` or protobuf files use the same framing:
- **Varint-Length-Delimited Streams** (`[varint len][protobuf bytes]` repeated until EOF):
  - `index.notes.pb`, `index.attachments.pb`, `index.search.pb`, `index.events.pb`
  - `notes/<NoteLayerUUID>` (always an **even** number of messages: `[Header, Payload]` pairs)
  - `search/<PdfAttachmentUUID>` (`kind = 1` in `index.search.pb`)
- **Single Raw Protobuf Messages** (parse the whole buffer directly, NO length prefix):
  - `schema.pb`
  - `search/<NoteLayerUUID>` (`kind = 0`/omitted in `index.search.pb`)
  - Decompressed `RichTextDocument` inside `f20.31.1.2` and `f21.32.1.2`

### 1.3 `schema.pb` Version Matrix

`schema.pb` holds `{1: schema_version}` and **must equal the maximum `min_schema_version`** across all objects in the archive:

| `min_schema_version` | Features Requiring This Version |
|---:|---|
| `24` | Document/page/template/attachment events, Fountain Pen, Ballpoint Pen, Brush Pen, Highlighter, Study Tape, Snapped Shapes + Fills (`f9`), Images/Stickers/Math Graphs (`f1`) |
| `25` | Pencil strokes (`f7` with `pen_type = 5` and Format-3 `tpl`) |
| `31` | Diagram Connectors / Arrows (`f22`) |
| `35` | Sticky Notes (`f20`) and modern Text Boxes / Flowchart Shapes (`f21`) |

---

## 2. Binary Encoding Primitives

### 2.1 Protobuf Wire Types & `proto3` Omission
Goodnotes serializes standard `proto3` wire format (`varint=0`, `fixed64=1`, `length_delimited=2`, `fixed32=5`).
- In `proto3`, default zero values (`0`, `0.0`, `""`, `false`) are omitted on the wire. **Parsers MUST treat missing fields as `0`/`0.0`/`""`** (e.g., `Point{y=1.0}` omits `x=0.0`; `ColorRGBA{a=1.0}` for black omits `r, g, b`; `LwwClock` counter `0` omits field `1`; `ZOrder` index `0` omits field `1`).
- Negative integers (e.g., `-404`, `-60`, `-1` in `RichText`) are encoded as **64-bit two's-complement unsigned varints** (10 bytes, `int64` / `uint64` semantics, NOT ZigZag `sint64`).

### 2.2 Apple `COMPRESSION_LZ4` (`bv41` / `bv4-` / `bv4$`) Stream Format

All stroke `tpl\x00` payloads (`f7.2`) and `RichTextDocument` payloads (`f20.31.1.2`, `f21.32.1.2`) are compressed using Apple's `libcompression` `COMPRESSION_LZ4` (`0x100`) frame format:

```
Stream := Chunk* "bv4$"
Chunk  := CompressedChunk | UncompressedChunk

CompressedChunk:
  4B  magic            = "bv41" (0x62 0x76 0x34 0x31)
  4B  uncomp_size      (uint32 little-endian)
  4B  comp_size        (uint32 little-endian)
  comp_size B          raw standard LZ4 block bytes (no frame header/checksum)

UncompressedChunk:
  4B  magic            = "bv4-" (0x62 0x76 0x34 0x2D)
  4B  uncomp_size      (uint32 little-endian)
  uncomp_size B        raw uncompressed bytes

EndMarker:
  4B  magic            = "bv4$" (0x62 0x76 0x34 0x24)
```

Inside a `bv41` raw LZ4 block:
1. Read `token` byte: `lit_len = token >> 4`, `match_len_base = token & 0x0F`.
2. If `lit_len == 15`, keep adding subsequent bytes until a byte `!= 255` is added.
3. Copy `lit_len` literal bytes to output. If stream cursor reached `comp_size`, block is complete (the final LZ4 sequence omits offset & match).
4. Read `offset` (`uint16` little-endian). `match_len = match_len_base + 4`.
5. If `match_len_base == 15`, keep adding subsequent bytes until a byte `!= 255` is added.
6. Copy `match_len` bytes from `len(output) - offset` byte-by-byte (overlapping RLE copies where `offset < match_len` are valid).

> **Writer Note:** Both `bv41` (compressed LZ4 block) and `bv4-` (uncompressed raw block) followed by `bv4$` are valid Apple `COMPRESSION_LZ4` streams. Pure-Python `compress_bv41()` in [`goodnotes_codec.py`](tools/goodnotes_codec.py) has been verified against macOS `/usr/lib/libcompression.dylib` on all 162/162 blobs in `Test.goodnotes`.

### 2.3 `tpl\x00` Binary Serialization (`troydhanson/tpl`)

Decompressed stroke blobs (`f7.2`) use the little-endian `tpl` binary serialization format:

```
Offset  Size  Field
0x00    4 B   magic       = "tpl\x00" (0x74 0x70 0x6C 0x00)
0x04    4 B   total_size  = uint32_le (exact byte length of the entire tpl buffer)
0x08    N B   format_str  = null-terminated ASCII format specification string
0x08+N  ...   payload     = packed little-endian values described by format_str
```

**Format Grammar Primitives Observed:**

| Token | Wire Size | Type & Semantics |
|---|---:|---|
| `v` | 2 B | `uint16_le` (version, opcode, cap flag, subpath op count, clockwise boolean) |
| `u` | 4 B | `uint32_le` — in Goodnotes, **reinterpreted bit-for-bit as IEEE-754 `float32_le`** everywhere **except** `Pencil` segment field `[0]` (`seed_u32`, a 32-bit unsigned PRNG seed) |
| `f` | 8 B | `float64_le` |
| `i` | 4 B | `int32_le` |
| `c` | 1 B | `uint8` |
| `S(...)` | sum of members | Inline packed struct of members inside parentheses |
| `A(...)` | `4 B + count * elem` | `uint32_le count` followed by `count` contiguous elements |

> **Lossless Round-Trip Tip:** Store `u` values as raw `uint32` during low-level parse/re-encode so `NaN`, `-0.0`, and `seed_u32` bit patterns round-trip identically.

### 2.4 CRDT Clocks, Ordering Keys, Tombstones & Colors

- **`replica_id` (`uint64`)**: Fixed 64-bit client replica identifier (`5589758967719760423` in `Test.goodnotes`).
- **Lamport Clocks (`uint64`)**:
  - `index.events.pb`: strictly monotonic event clock (`1794351892233 .. 1794351892602`).
  - `notes/*`: per-object edit Lamport clock in `NoteObjectHeader.lamport` (`1715405 .. 1715602`).
- **`LwwClock` (`{1: uint32 counter, 2: uint32 tiebreaker}`)**: Last-Writer-Wins register tag. In `notes/*`, `NoteObjectHeader.revision` is **always byte-identical** to the payload's own `revision` field (`f1.15`, `f7.15`, `f9.15`, `f20.3`, `f21.3`, `f22.3`).
- **`ZOrder` (`{1: {1: uint32 index, 2: uint32 tiebreaker}}`)**: Render back-to-front by sorting `(index, tiebreaker)` ascending.
- **Page Order Keys (`CreatePage.order_key`)**: Fractional ASCII strings sorted lexicographically (`"4BPpG1" < "4BPpG2" < "A3X5-" < "F3Vq1"`). Allows O(1) page insertion/reordering without renumbering other pages.
- **Soft-Delete Tombstones**: Erased items remain in `notes/<NoteLayerUUID>` with:
  - `NoteObjectHeader.is_deleted = 1`
  - `StrokeItem.is_deleted = 1` (plus `tpl` cleared to `width = 0.0` and empty arrays) or `ShapeFillItem.is_deleted = 1` (plus `bounding_box` set to `(NaN, NaN, NaN, NaN)`).
  - **Renderers MUST filter out any record where `header.is_deleted == 1` or `payload.is_deleted == 1`.**
- **`ColorRGBA`**: 4 `float32` fields (`1=r, 2=g, 3=b, 4=a`) normalized to `[0.0, 1.0]`.
- **Timestamps**: Unix epoch milliseconds stored as IEEE-754 `double` (`fixed64`, e.g. `1795106884366.638` = `2026-11-19T16:48:04.367Z`).

---

## 3. Coordinate System, Units & UUID Architecture

### 3.1 Canvas Units (132 PPI, Top-Left Origin)

Goodnotes operates in a **top-left origin, `+X` right, `+Y` down** coordinate space at exactly **132 pixels/units per inch** (`11/6` PDF points, since `72 pt/in × 11/6 = 132`):

$$\text{goodnotes\_units} = \text{pdf\_points} \times \frac{11}{6} \qquad \left(1\text{ mm} = \frac{132}{25.4} \approx 5.19685\text{ units}\right)$$

Verified directly against `Test.goodnotes` templates:
- **A4 PDF** (`MediaBox [0 0 595.28 841.89]` pt): `595.28 × 11/6 = 1091.3467`, `841.89 × 11/6 = 1543.4650` (exact match to `CreatePageTemplate.page_size`).
- **US Letter PDF** (`MediaBox [0 0 612 792]` pt): `612 × 11/6 = 1122.0`, `792 × 11/6 = 1452.0` (exact match to Page 4 `CreatePageTemplate.page_size`).
- **0.3 mm Pen Width**: `0.3 × (132 / 25.4) = 1.559055` units (exact match to `StrokeItem` default width `1.5590552`).
- **Template Ruling (`Event[4]` Black Ruled)**: `line_spacing = 32.083336 = 17.5 pt × 11/6`; `stroke_thickness = 0.916667 = 0.5 pt × 11/6`; `row_pitch_minus_stroke = 31.166668 = 32.083336 - 0.916667`.
- **Template PDF Rendering**: PDF uses bottom-left Y-up; Goodnotes' built-in template PDFs apply `1 0 0 -1 0 841.89 cm` internally so PDF content aligns with Y-down coordinates.

### 3.2 Critical UUID Rule: `NoteLayerUUID = PageUUID + 1`

There is **no explicit `note_layer_id` field** inside `CreatePage`. Instead, every page's note layer UUID is deterministically computed by incrementing the 128-bit integer value of `page_id` by **1** (preserving uppercase hyphenated formatting):

```python
note_layer_uuid = str(uuid.UUID(int=uuid.UUID(page_uuid).int + 1)).upper()
```

Verified 4/4 on `Test.goodnotes` (applies equally to UUIDv4 and UUIDv5):

| Page | `order_key` | `CreatePage.page_id` | Derived `NoteLayerUUID` (`+1`) | UUID Version |
|---:|---|---|---|---|
| 1 | `4BPpG1` | `23B4A80F-6A3A-40D9-A587-1CFB895B6A38` | `23B4A80F-6A3A-40D9-A587-1CFB895B6A39` | v4 |
| 2 | `4BPpG2` | `9AFA8DE4-2C4A-400D-B88F-C32043C9ED9E` | `9AFA8DE4-2C4A-400D-B88F-C32043C9ED9F` | v4 |
| 3 | `A3X5-` | `45ACB5BF-26A6-47E8-B407-584D5408ADB1` | `45ACB5BF-26A6-47E8-B407-584D5408ADB2` | v4 |
| 4 | `F3Vq1` | `EE6C27D0-0C00-574B-8943-1650E68D2BC0` | `EE6C27D0-0C00-574B-8943-1650E68D2BC1` | v5 |

### 3.3 Attachment Indirection (`LogicalAttachmentUUID` vs `StorageBlobUUID`)

`CreatePageTemplate.logical_attachment_id` and `ImageItem.attachment_id` reference **logical attachment UUIDs**, NOT directly file names under `attachments/`. Always resolve via `index.attachments.pb` (or `RegisterAttachment.storage_blob_id`):
- Example on Page 4 (Scanned PDF): `CreatePageTemplate` references `EED94C43-D02B-526A-9E73-43CEA4E71461`, which `index.attachments.pb` maps to `attachments/389FABA8-B298-4F6B-8CB1-8939C20F94EA`.

### 3.4 Sticky Note Child Ink Transform

Strokes drawn onto a Sticky Note (`f20`) set:
- `NoteObjectHeader.parent_container_id` (`f20`) = `StickyNote.id`
- `StrokeItem.parent_ref` (`f7.100`) = `{1: StickyNote.id}`
- `StrokeItem.local_offset` (`f7.6`) = `(-initialStickyOrigin.x, -initialStickyOrigin.y)`

Inside the stroke's `tpl\x00` payload, coordinates remain in **original page space** at the moment of drawing! To place a child stroke on screen if the sticky note is moved:

$$\text{render\_pos} = \text{tpl\_pos} + \text{f7.6} + \text{parent\_sticky.origin}$$

Verified on `3AEAA4E4-...`: parent sticky note `BC607A9F-...` is at `(771.1153, 203.5629)`, `f7.6 = (-771.1153, -203.5629)`, `tpl_start = (783.33, 279.40)` → local sticky offset `(12.22, 75.84)` → `render_pos = (783.33, 279.40)`.

### 3.5 Critical Arc Sweep Convention (CoreGraphics Y-Up vs SVG/Canvas Y-Down)

In Format-2 `tpl\x00` stroke outlines (`op 3` circular arc, `op 6` elliptical arc), Goodnotes stores angles in standard **Y-down radians** (`0` = `+X`, `π/2` = `+Y`), **but** stores the `clockwise` boolean using **Apple CoreGraphics / Quartz Y-up convention**:
- When converting to any **Y-down renderer** (SVG `<path d="... A ...">`, HTML5 Canvas, Skia, PDF after Y-flip):
  - `clockwise == 1` (`True`) → sweep in **decreasing-angle** direction (`delta = (startAngle - endAngle) mod 2π`, SVG `sweep-flag = 0`).
  - `clockwise == 0` (`False`) → sweep in **increasing-angle** direction (`delta = (endAngle - startAngle) mod 2π`, SVG `sweep-flag = 1`).
  - `large-arc-flag = 1` if `delta > π` else `0`.

---

## 4. File-by-File Wire Specification

### 4.1 `schema.pb` and `index.*.pb`

- **`schema.pb`** (single raw protobuf):
  - `1 (varint)`: `schema_version` (`35` in `Test.goodnotes`).
- **`index.notes.pb`** & **`index.attachments.pb`** (delimited protobuf stream):
  - `1 (string)`: `uuid` (`NoteLayerUUID` or `LogicalAttachmentUUID`)
  - `2 (string)`: `path` (`"notes/<UUID>"` or `"attachments/<BlobUUID>"`)
- **`index.search.pb`** (delimited protobuf stream):
  - `1 (string)`: `uuid` (`NoteLayerUUID` or `PdfAttachmentUUID`)
  - `2 (string)`: `path` (`"search/<UUID>"`)
  - `3 (varint)`: `kind` (`0`/omitted = `PageSearchIndex`, `1` = `PdfSearchPage` stream)

### 4.2 `index.events.pb` Event Log

Each record is `EventEnvelope { string entity_uuid = 1; <oneof event_tag> = ...; }`:

| Tag | Event Name | Key Fields | Observed Purpose |
|---:|---|---|---|
| `30` | `CreateDocument` | `1:docId`, `2:LwwString(title)`, `3:LwwString(folderId)`, `6:LwwBytes("P")`, `7:LwwString(parentFolderId)`, `9:lang("auto")`, `10:tsMs(f64)`, `11:eventId`, `13:replicaId`, `14:lamport`, `17:""`, `18:""`, `19:LwwEmpty`, `20:ver(24)` | Creates notebook root metadata (`Test`) |
| `6` | `RegisterAttachment` | `1:logicalAttId`, `2:storageBlobId`, `5:byteSize`, `6:docId`, `10:tsMs`, `11:eventId`, `12:PdfMeta{1:pages, 2:ver}` (PDFs) or `""` (images), `14:replicaId`, `15:lamport`, `16:ver(24)` | Registers every PDF/PNG/JPEG blob |
| `2` | `CreatePageTemplate` | `1:docId`, `2:tplId`, `4:logicalAttId`, `5:pdfPage(1)`, `6:isBuiltin(1)`, `7:lineSpacing(f64)`, `8:Size(pageSize)`, `9:tplName`, `10:tsMs`, `11:eventId`, `12:LwwDouble(lineSpacing)`, `13:LwwUint32(hasRuling)`, `15:replicaId`, `16:lamport`, `17:LwwUint32(paperTheme: 1=light, 2=dark)`, `18:RulingLayout{1:Rect, 2:pitchMinusStroke_f32, 3:stroke_f32, 5:rulingKind(1=dot,2=line)}`, `19:LwwEmpty`, `21:ver(24)` | Declares page geometry, paper theme, ruling grid, and backing PDF |
| `54` | `CreatePage` | `1:docId`, `2:pageId`, `3:LwwString(tplId)`, `4:LwwString(orderKey)`, `10:tsMs`, `11:eventId`, `13:replicaId`, `14:lamport`, `15:ver(24)`, `17:PageStyleLww{1:{2:{1:ColorRGBA(0.867,0.867,0.867,1), 2:ColorRGBA(1,1,1,1)}}, 2:LwwClock}` | Creates a page and places it in document order |
| `10` | `UpdateCurrentPage` | `1:docId`, `2:activePageId`, `3:editorSessionId("DocumentEditor:<UUID>")`, `10:tsMs`, `11:eventId`, `13:replicaId`, `14:lamport`, `15:ver(24)` | Persists last viewed page |
| `102` | `NoteLayerCheckpoint` | `1:noteLayerId`, `10:tsMs`, `11:eventId`, `13:replicaId`, `14:lamport`, `15:ver(24)`, `16:docId` | Records note layer save checkpoint |
| `103` | `PdfSearchIndexed` | `1:pdfAttId`, `2:docId`, `10:tsMs`, `11:eventId`, `14:status(1)`, `16:runId`, `18:replicaId`, `19:lamport`, `20:ver(24)` | Marks PDF search extraction done |
| `104` | `PageSearchIndexed` | `1:docId`, `2:noteLayerId`, `10:tsMs`, `11:eventId`, `12:contentHash_u64`, `13:lang`, `14:status(1)`, `15:runId`, `17:replicaId`, `18:lamport`, `19:ver(24)` | Marks page OCR/HWR indexing done (`12` matches `search/<layer>.field 12`) |
| `105` | `SearchIndexJob` | `1:jobType(1=page, 0/omitted=pdf)`, `2:docId`, `3:pdfAttId`, `4:noteLayerId`, `5:contentHash_u64`, `6:lang`, `10:tsMs`, `11:eventId`, `13:replicaId`, `14:lamport`, `15:ver(24)` | Enqueues search indexing job |

### 4.3 `notes/<NoteLayerUUID>` Paired Object Stream

Each object consists of **two consecutive length-delimited messages**: `[NoteObjectHeader, NoteObjectPayload]`.

#### `NoteObjectHeader`
| Field | Wire Type | Meaning |
|---:|---|---|
| `1` | `string` | `object_id` (UUID) |
| `2` | `LwwClock` | `revision` (byte-identical to payload's revision field) |
| `3` | `varint` | `is_deleted` (`1` = tombstoned/erased; omitted = active) |
| `4` | `string` | `attachment_id` (present only on `ImageItem` tag `1`) |
| `8` | `varint` | `replica_id` (`uint64`) |
| `9` | `varint` | `lamport` (`uint64`) |
| `14` | `varint` | Constant `5381` observed on every object across all pages |
| `16` | `varint` | `min_schema_version` (`24`, `25`, `31`, or `35`) |
| `20` | `string` | `parent_container_id` (UUID of parent Sticky Note `f20`) |

#### `NoteObjectPayload` Variants (Selected by Single Outer Field Tag)

1. **Tag `1` — `ImageItem` (Photos, Stickers/Elements, Math Assist Graphs)**
   - `1`: `id` (`string`)
   - `2`: `bounding_box` (`Rect{topLeft, size}`)
   - `3`: `center_frame` (`Rect{center, size}` where `center = topLeft + size / 2`)
   - `4`: `attachment_id` (`string`, logical attachment UUID)
   - `5`: `z_order` (`ZOrder`)
   - `6`: `is_sticker_element` (`uint32`: `1` for Goodnotes Elements/Stickers)
   - `7`: `element_asset_id` (`string`: element catalog UUID)
   - `15`: `revision` (`LwwClock`)
   - `18`: `min_schema_version` (`24`)
   - `19`: `math_graph_id` (`string`: equals `id` on Math Assist graphs)
   - `20`: `math_graph_json` (`bytes`: UTF-8 JSON containing `rect`, `id`, `imageItemId`, and `model` with `associatedLines` [pageId, stroke `lineId`, `bounds`, `latex`], `functions` [`color`, `displayName`, `serializablePlottableFunctions` with `argument`/`definition`, `laTeX`], `xDomain`, `yDomain`)

2. **Tag `7` — `StrokeItem` (All Pens, Pencil, Highlighter, Study Tape, Snapped Shapes)**
   - `1`: `id` (`string`)
   - `2`: `compressed_tpl` (`bytes`: Apple `bv41` LZ4-compressed `tpl\x00` payload)
   - `3`: `pen_type` (`uint32`: `0`/omitted = Ballpoint / Highlighter / SnappedShape, `1` = Fountain Pen / Brush Pen / Study Tape, `5` = Pencil)
   - `4`: `color` (`ColorRGBA`)
   - `5`: `is_highlighter` (`uint32`: `1` for Highlighter)
   - `6`: `local_offset` (`Point`: empty normally; `(-parent.x, -parent.y)` on sticky-note ink)
   - `7`: `z_order` (`ZOrder`)
   - `9`: `snapped_shape` (`SnappedShapeGeometry`: `1=Polyline{repeated Point 1}`, `4=Ellipse{1:center, 2:radii, 3:rotation_rad}`, `5={2:1}`, `15=stroke_width_f32`)
   - `14`: `is_deleted` (`uint32`: `1` when tombstoned)
   - `15`: `revision` (`LwwClock`)
   - `20`: `tape_attributes` (`{1: ""}` on Study Tape; empty bytes otherwise)
   - `21`: `min_schema_version` (`24`, or `25` for Pencil)
   - `100`: `parent_ref` (`{1: string parent_id}` present on sticky-note ink)

3. **Tag `9` — `ShapeFillItem` (Semi-Transparent Fill Paired with Snapped `StrokeItem`)**
   - `1`: `id` (`string`)
   - `2`: `bounding_box` (`Rect`: `(NaN, NaN, NaN, NaN)` when tombstoned)
   - `3`: `z_order` (`ZOrder`)
   - `4`: `fill_geometry` (`{1: Polyline{repeated Point 1}}` or `{4: Ellipse{1:center, 2:radii, 3:rotation_rad}}`)
   - `5`: `associated_stroke_id` (`string` UUID of corresponding `StrokeItem`)
   - `6`: `""`
   - `7`: `fill_color` (`ColorRGBA`, observed `(1, 1, 1, 0.1)`)
   - `14`: `is_deleted` (`uint32`: `1` when tombstoned)
   - `15`: `revision` (`LwwClock`)
   - `18`: `min_schema_version` (`24`)

4. **Tag `20` — `StickyNoteItem` (`min_schema_version = 35`)**
   - `1`: `id`, `2`: `35`, `3`: `revision`, `7`: `z_order`
   - `20`: `transform` (`{1: Point origin, 3: f32 scale(1.0)}`)
   - `21`: `size_constraints` (`{2: {1: width(256), 2: height(256), 3: max_height(+inf)}}`)
   - `30`: `background_color` (`ColorRGBA`, yellow sticky observed `(0.9804, 0.9059, 0.4706, 1.0)`)
   - `31`: `rich_text` (`RichTextContainer`)
   - `32`: `author_id` (`string` lowercase UUID)
   - `33`: `author_name` (`string`)
   - `40`: `1`, `41`: `1`

5. **Tag `21` — `TextOrShapeItem` (Text Boxes & Flowchart/Diagram Nodes, `min_schema_version = 35`)**
   - `1`: `id`, `2`: `35`, `3`: `revision`, `7`: `z_order`
   - `9`: `is_textbox` (`1` for Text Box; `0`/omitted for Flowchart/Diagram nodes)
   - `20`: `transform` (`{1: Point origin, 3: f32 scale(1.0)}`)
   - `21`: `size_constraints` — either `2: FixedSizeBox{1:w, 2:h, 3:maxH(+inf)}` (shapes) or `3: AutoSizeBox{1:minW(32), 2:maxW(600), 3:minH(32), 4:maxH(+inf)}` (text box)
   - `22`: `shape_kind`:
     - `1: {}` (empty) → Sharp rectangle (Text Box)
     - `1: {1: f32 cornerRadius}` → Rounded rectangle / oval pill (`80.0` observed)
     - `3: {1: {1: repeated PolygonVertex{1:Point normalized[0..1], 2:1, 3:f32 cornerRadius(5.0)}, 2: closed(1)}}` → Normalized polygon (e.g. Triangle `(0.5,0),(0,1),(1,1)`, Diamond `(0.5,0),(1,0.5),(0.5,1),(0,0.5)`)
   - `30`: `fill_style` (`{1: {1: ColorRGBA}}`)
   - `31`: `border_style` (`{1: f32 width, 2: {1: ""}, 3: {1: ColorRGBA}}`)
   - `32`: `rich_text` (`RichTextContainer` with `2: measured_size`, `10: TextInsets(top, left, bottom, right)`)
   - `33`: `shadow` (`DropShadow{1:{4: f32 opacity(0.2)}, 3:{2: f32 blurRadius(5.0)}}`)

6. **Tag `22` — `ConnectorItem` (Diagram Arrows/Connectors, `min_schema_version = 31`)**
   - `1`: `id`, `2`: `31`, `3`: `revision`, `7`: `z_order`
   - `20`: `curved_path` (`{1:{1:startPt}, 2:controlPt, 3:{1:endPt}}`) — quadratic Bezier connector
   - `21`: `straight_or_elbow_path` (`{1:{1:startPt}, 3:{1:endPt}, 4:1, 5:{2:midpoint}}`) — straight/elbow connector
   - `31`: `end_arrowhead` (`1` = arrowhead at `end`)
   - `32`: `stroke_style` (`{1: f32 width(3.0), 2: {1: ""}, 3: {1: ColorRGBA}}`)

### 4.4 The Three `tpl\x00` Stroke Formats

> **CRITICAL WIDTH WARNING:** Format 1 and Format 3 store **full stroke widths (diameters)**, whereas Format 2 stores **half-widths (radii)** (`fullWidth = 2 * halfWidth`).

#### Format 1 — Ballpoint / Highlighter / Snapped-Shape Stub (`pen_type = 0`)
Format string: `vuA(v)A(S(uu))A(S(uuuu))vA(f)`

| Index | TPL Type | Name | Meaning |
|---:|---|---|---|
| `[0]` | `v` | `version` | `2` |
| `[1]` | `u` (`f32`) | `full_width` | Constant full stroke width (e.g. `1.559055` = 0.3 mm, `24.0` highlighter, `0.0` if deleted) |
| `[2]` | `A(v)` | `ops` | `0` = moveTo (consumes 1 entry from `[3]`), `1` = quadCurveTo (consumes 1 entry from `[4]`) |
| `[3]` | `A(S(uu))` | `move_points` | `(x, y)` per `op == 0` |
| `[4]` | `A(S(uuuu))` | `quad_segments` | `(cx, cy, ex, ey)` quadratic Bezier per `op == 1` |
| `[5]` | `v` | `cap_flag` | `1` |
| `[6]` | `A(f)` | `extra_doubles` | `[]` (empty) |

*Note:* Snapped shapes (`f7.9` non-empty) leave `[2]`, `[3]`, `[4]` empty and store final snapped geometry in `StrokeItem.snapped_shape` (`f7.9`).

#### Format 2 — Fountain Pen / Brush Pen / Study Tape (`pen_type = 1`)
Format string: `vA(v)A(u)A(u)A(v)A(v)A(u)A(u)A(u)A(u)A(v)`

Format 2 stores **both** the raw variable-width centerline AND the pre-tessellated closed outline contours (`fill-rule="nonzero"`):

| Index | TPL Type | Name | Meaning |
|---:|---|---|---|
| `[0]` | `v` | `version` | `2` |
| `[1]` | `A(v)` | `centerline_ops` | Circular nib (Fountain/Brush): `0` = moveTo (3 floats in `[2]`), `1` = quadTo (6 floats in `[3]`). Elliptical/chisel nib (Study Tape, `f7.20={1:""}`): `4` = ellipticalMoveTo (4 floats in `[2]`), `5` = ellipticalQuadTo (9 floats in `[3]`) |
| `[2]` | `A(u)` | `start_floats` | Circular (`op 0`): `[x, y, halfWidth]`. Elliptical (`op 4`): `[x, y, majorR, angle]` |
| `[3]` | `A(u)` | `segment_floats` | Circular (`op 1`): `[cx, cy, cHalfW, ex, ey, eHalfW]`. Elliptical (`op 5`): `[cx, cy, cR, ex, ey, eR, cAngle, eAngle, flatness=0.1]` |
| `[4]` | `A(v)` | `subpath_op_counts` | Number of outline commands in each closed subpath; `len([4]) == count(c_ops in {1, 5})` and `sum([4]) == len([5])` |
| `[5]` | `A(v)` | `outline_ops` | `0` = moveTo, `1` = quadTo (`PQuadCurveTo`), `2` = cubicTo (`PCubicCurveTo`), `3` = circular arc (`PArc`), `6` = elliptical arc (`PEllipticalArc`) |
| `[6]` | `A(u)` | `outline_moves` | 2 floats `(x, y)` per `op == 0` |
| `[7]` | `A(u)` | `outline_quads` | 4 floats `(cx, cy, ex, ey)` per `op == 1` |
| `[8]` | `A(u)` | `outline_cubics` | 6 floats `(c1x, c1y, c2x, c2y, ex, ey)` per `op == 2` |
| `[9]` | `A(u)` | `outline_arcs` | Circular (`op 3`): 5 floats `(cx, cy, r, startAngle, endAngle)`. Elliptical (`op 6`): 7 floats `(cx, cy, rx, ry, startAngle, endAngle, rotation)` |
| `[10]` | `A(v)` | `outline_arc_cw` | 1 `uint16` (`0` or `1`) per arc (`op 3` or `op 6`) in CoreGraphics Y-up convention |

#### Format 3 — Pencil (`pen_type = 5`, `min_schema_version = 25`)
Format string: `vuA(v)A(S(uuuuu))A(S(uuuuuuuuuuu))A(S(uu))A(v)A(S(uu))A(S(uuuu))A(u)`

| Index | TPL Type | Name | Meaning |
|---:|---|---|---|
| `[0]` | `v` | `version` | `1` |
| `[1]` | `u` (`f32`) | `base_full_width` | Base width (`1.559055`) |
| `[2]` | `A(v)` | `ops` | `0` = moveTo (1 entry in `[3]`), `1` = quadCurveTo (1 entry in `[4]`) |
| `[3]` | `A(S(5u))` | `starts` | `(x, y, paramA, paramB, pressure)` |
| `[4]` | `A(S(11u))` | `quad_segments` | `(seed_u32, cx, cy, cParamA, cParamB, cPressure, ex, ey, eParamA, eParamB, ePressure)` |
| `[5..9]` | arrays | `reserved` | Always empty `[]` across all 23 observed pencil strokes |

*Note on `paramA`, `paramB`, `pressure`, `seed_u32`:* `seed_u32` is a raw 32-bit unsigned grain seed per segment; `pressure` varies smoothly (`0.195..2.005`); `paramA`/`paramB` stay constant across all strokes in a batch (three distinct pairs observed across the test strokes: `(0.8057, 0.8142)`, `(0.6121, 0.7210)`, `(0.2964, 1.0907)` — likely stylus tilt/shading state at stroke time).

### 4.5 `RichTextContainer` & Compressed `RichTextDocument` (`f20.31` / `f21.32`)

- Outer `RichTextContainer`:
  - `1`: `RichTextContent` (`2`: `bv41`-compressed `RichTextDocument`, `3`: 8-byte deterministic content hash, `4`: `1`)
  - `2`: `measured_size` (`Size`, e.g., `116 × 29`)
  - `5`: `default_style` (`1`: `DefaultCharStyle{3:ColorRGBA, 30:fontFamily("Helvetica Neue"), 40:fontSize, 60:-60, 70:-20.0}`, `2`: `DefaultParagraphStyle`)
  - `10`: `insets` (`{1:top, 2:left, 3:bottom, 4:right}`, e.g., `(10, 10, 10, 10)` on Text Box)
- Decompressed `RichTextDocument` (single raw protobuf):
  - `repeated TextRun runs = 1`, each with:
    - `1`: `string text`
    - `2`: `CharStyle`: `3=textColor`, `4=hyperlinkUrl`, `5=highlightColor`, `40=fontSize` (`-404.0` = inherit from `default_style`), `60=-404`, `70=-404.0`
    - `3`: `ParagraphStyle`: `4=alignment` (`0`/omitted = left, `2` = center)
- **Internal Goodnotes Page Hyperlink Format** (observed in `D5D66F06`):
  ```
  https://app.goodnotes.com/documents/?anchor=<urlEncode(base64("page-" + pageUUID))>#<base64(documentUUID)>
  ```
  Example: `anchor=cGFnZS05QUZBOERFNC0yQzRBLTQwMEQtQjg4Ri1DMzIwNDNDOUVEOUU%3D` decodes to `page-9AFA8DE4-2C4A-400D-B88F-C32043C9ED9E`, and fragment `NjhDRkE4MDUtNDdDQi00MTk2LTk2RjMtRkFGQkFDMjRBNjY3` decodes to `68CFA805-47CB-4196-96F3-FAFBAC24A667`.

### 4.6 Search Index Files (`search/*`)

- **`search/<NoteLayerUUID>`** (`PageSearchIndex`, single raw protobuf):
  - `3` (repeated `string`): plain text strings extracted from typed text items (`f20`/`f21`), parallel to `4` and `17`.
  - `4` (repeated `TypedTextLayout`): `{repeated Token 2: {1:startChar, 2:charLen, 3:Rect localBox}, 3:AffineTransform{1..4:matrix, 5:tx, 6:ty}}`.
  - `5` (`string`): `page_id` (**Page UUID**, i.e., `NoteLayerUUID - 1`).
  - `6` (repeated `HandwritingWordCandidate`): `1:Rect bbox`, `3:repeated candidates`, `4:packed f32 scores`, `5:repeated normCandidates`, `6:packed f32 confidences`, `7:repeated SearchStrokeRef{1:internalId, 2:Rect, 3:strokeUUID, 4:repeated Point, 5:ColorRGBA, 6:maxWidth}`, `9:packed f32 scores`, `10:repeated rawCandidates`, `11:locale`.
  - `12`: `content_hash_u64` (matches `PageSearchIndexed.12` / `SearchIndexJob.5`).
  - `13`: `"auto"`, `14`: `5.0`, `15`: `23101502`, `16`: `1`.
- **`search/<PdfAttachmentUUID>`** (`PdfSearchPage`, delimited stream):
  - `{2: uint32 page_number, 3: string extracted_text}`.

---

## 5. Complete Tool & Page-Style Catalog (Observed in `Test.goodnotes`)

### 5.1 Four Page Styles

| Page | Order Key | Template Name | PDF Dimensions | Paper Theme / Ruling | Backing Blob |
|---:|---|---|---|---|---|
| 1 | `4BPpG1` | `417A3734-..._a4_1_1 - Blue` | 595.28×841.89 pt (A4) | `theme=1`, no ruling | `C3BDD217-...` (`svg2pdf`, cyan `#51d7f5` + `#0a9dbf` spine) |
| 2 | `4BPpG2` | `238EE861-..._a4_1_3 - Black` | 595.28×841.89 pt (A4) | `theme=2`, `ruling_kind=2` (ruled lines, `32.083` pitch) | `D08775A5-...` (`svg2pdf`, `#333333` bg + `#58595b` lines) |
| 3 | `A3X5-` | `CC365888-..._a4_1_2 - White` | 595.28×841.89 pt (A4) | `theme=1`, `ruling_kind=1` (dotted grid, `29.333` pitch) | `8DF7E563-...` (`svg2pdf`, `#ffffff` bg + `#d0d2d3` dots) |
| 4 | `F3Vq1` | `""` (Scanned Document) | 612×792 pt (US Letter) | Imported PDF (`is_builtin=false`, no ruling) | `389FABA8-...` (iOS Quartz PDF: JPEG + `3 Tr` invisible OCR) |

### 5.2 Every Tool Used on Page 2 (`9AFA8DE4-...9F`) & Page 1/3

| Tool | Payload Tag & Discriminator | TPL Format | Example UUID in `Test.goodnotes` | Notes / Visual Content |
|---|---|---|---|---|
| **Fountain Pen** | `f7`, `pen_type=1` | Format 2 (circular nib) | `2F69D2BA-...` (`z=0`) | `"Hello how are you?"`, `"f(x) = 1x + 2"`, and Page 3 `"Hi different template"` |
| **Brush Pen** | `f7`, `pen_type=1` | Format 2 (circular nib) | `D9B1D95A-...` (`z=49`) | `"Brush Pen"` (white) & `"different color"` (red `#f33f3f`) — wider pressure modulation (`halfWidth` up to `2.15`) |
| **Ballpoint Pen** | `f7`, `pen_type=0` | Format 1 | `839450B0-...` (`z=41`) | `"Ball Pen"` (`full_width = 1.559`), Page 1 Cover dot `46E396A7-...` |
| **Pencil** | `f7`, `pen_type=5`, `ver=25` | Format 3 | `5062CBCA-...` (`z=25`), `FC62E119-...` (`z=74`) | `"This is the Pencil"` (`rgba(0.66,0.65,0.63,1)`) + dark pencil `"lol"` (`rgba(0.36,0.36,0.35,1)`) |
| **Highlighter** | `f7`, `pen_type=0`, `is_highlighter=1` | Format 1 (or `f7.9` snapped) | `912CB96D-...` (`z=19`), `FD309AE4-...` (`z=20`) | Straight snapped yellow & green highlights (`a=0.5`, `width=24.0`) under `"how are"` |
| **Study Tape** | `f7`, `pen_type=1`, `f7.20={1:""}` | Format 2 (`ops 4, 5, 6`) | `FF4619F8-...` (`z=58`), `3F1810DC-...` (`z=57`) | Opaque green (`#63dd57`) & coral-red (`#ff5f67`) chisel-nib tape (`majorR=18.0`) masking `"Hello"` & `"you"` |
| **Eraser (Tombstones)** | `hdr.3=1`, `f7.14=1` / `f9.14=1` | Empty `tpl` / `NaN` rect | `08DCAC8A-...`, `5027A253-...` | 18 tombstoned objects total across Pages 1–3; skipped when rendering |
| **Snapped Shapes + Fill** | `f7` (`f7.9` populated) + paired `f9` | Format 1 (empty path arrays) | `2C3EAC4C-...` + `1B5AAB08-...` | Quadrilateral, circle, ellipse, triangle, and 2 snapped arrows with 10% white `ShapeFillItem` |
| **Flowchart Shapes** | `f21`, `ver=35`, `is_textbox=0` | N/A | `7F89B59D-...`, `10181F73-...`, `8D7C3B48-...` | Rounded oval, rounded triangle, rounded diamond (`3px` white border, 10% white fill) |
| **Connectors / Arrows** | `f22`, `ver=31`, `end_arrowhead=1` | N/A | `3D67035A-...` (straight), `09F51264-...` (curved) | Upward flowchart arrows (`f22.21` straight/elbow & `f22.20` quadratic Bezier) |
| **Text Box** | `f21`, `ver=35`, `is_textbox=1` | `bv41` `RichTextDocument` | `D5D66F06-...` (`z=94`) | `"This is text"` (`"This"` underlined page link, `"is"` plain, `"text"` pink highlight, drop shadow) |
| **Sticky Note + Child Ink** | `f20`, `ver=35` + child `f7` (`f7.100`) | `bv41` `RichText` + child Format 2 | `BC607A9F-...` (`z=97`) + `3AEAA4E4-...` (`z=98`) | Yellow 256×256 sticky note `"Sticky note"` (author `"Tim Schuchardt"`) + `"Annotated"` ink |
| **Photo (Image)** | `f1` | N/A | `2814BC74-...` (`z=95`) | Embedded PNG `D62A8C11-...` (1255×998, document cutout) |
| **Sticker / Element** | `f1`, `is_sticker_element=1` | N/A | `B1F57681-...` (`z=96`) | Embedded JPEG `E745B161-...` (1179×1363, `"I hope it's a PS5"` sticker) |
| **Math Assist Graph** | `f1`, `f1.19` + `f1.20` JSON | N/A | `FE157E62-...` (`z=125`) | Plotted PNG `A438C528-...` (`712×712`) linked to Fountain Pen strokes `"f(x) = 1x + 2"` |

---

## 6. Implementer's Guide (Reading, Rendering & Writing)

### 6.1 Algorithm: Reading & Rendering a `.goodnotes` File

1. **Open ZIP** and parse `schema.pb` (raw protobuf) to check compatibility (`<= 35`).
2. **Parse Index Files** (delimited protobuf streams):
   - Build `note_paths[uuid] = path` from `index.notes.pb`.
   - Build `att_paths[logical_uuid] = path` from `index.attachments.pb`.
3. **Replay `index.events.pb`** (delimited protobuf stream):
   - Collect `CreatePageTemplate` (`tag 2`) keyed by `template_id` (giving `page_size`, `logical_attachment_id`, `pdf_page_number`, `paper_theme`, `ruling_layout`).
   - Collect `CreatePage` (`tag 54`) and **sort lexicographically by `order_key`**.
   - For each page, derive `note_layer_id = UUID(int = UUID(page_id).int + 1)`.
4. **Render Each Page** on a canvas of size `template.page_size` (132 PPI, Y-down):
   - Draw page background by rendering page `template.pdf_page_number` from `att_paths[template.logical_attachment_id]` scaled by `132/72` (`11/6`).
   - Parse `notes/<note_layer_id>` as pairs `[Header, Payload]`. Discard any object with `header.is_deleted == 1` or `payload.is_deleted == 1`.
   - Build `sticky_origins[id] = origin` for all active `StickyNoteItem` (`f20`) records.
   - Sort remaining active objects by `(z_order.index, z_order.tiebreaker)` ascending.
   - Draw each element:
     - `f1`: draw image `att_paths[attachment_id]` in `bounding_box`.
     - `f9`: fill `polygon` or rotated `ellipse` with `fill_color`.
     - `f7`: if `parent_container_id` is set, add `dx = local_offset.x + sticky_origins[parent].x`, `dy = local_offset.y + sticky_origins[parent].y`. If `snapped_shape` (`f7.9`) is set, stroke polyline/ellipse with `stroke_width`; otherwise decompress `f7.2` (`bv41`), parse `tpl\x00`, and render Format 1/3 centerline with `full_width` or Format 2 filled `outlines` (`nonzero` fill rule, remembering CoreGraphics arc sweep flip in Y-down!).
     - `f20` / `f21` / `f22`: render sticky note card + `RichText`, flowchart/text box + `RichText`, and connectors + optional arrowheads.

### 6.2 Algorithm: Writing a Minimal Valid `.goodnotes` File

See `GoodnotesBuilder` in [`goodnotes_codec.py`](tools/goodnotes_codec.py) for a working, round-trip-tested implementation:
1. Choose a `replica_id` (64-bit random uint), `document_id` (UUIDv4), `folder_id` (UUIDv4), and start monotonic `event_lamport` and `note_lamport` counters.
2. Emit `CreateDocument` (`tag 30`) into `index.events.pb`.
3. For each template/attachment blob: generate `att_id`, store bytes at `attachments/<att_id>`, record `(att_id, "attachments/" + att_id)` in `index.attachments.pb`, and emit `RegisterAttachment` (`tag 6`).
4. For each page:
   - Emit `CreatePageTemplate` (`tag 2`) with `page_size = (pdf_w_pt * 11/6, pdf_h_pt * 11/6)`.
   - Generate `page_uuid = uuid.uuid4()` and **derive `note_uuid = UUID(int = page_uuid.int + 1)`** (CRITICAL!).
   - Emit `CreatePage` (`tag 54`) with monotonically increasing ASCII `order_key` (`"4BPpG1"`, `"4BPpG2"`, ...).
5. Build `notes/<note_uuid>` as alternating delimited `[NoteObjectHeader, NoteObjectPayload]` pairs, ensuring `header.revision == payload.revision`, `header.const_5381 = 5381`, and `header.min_schema_version` matches the item (`24`, `25`, `31`, or `35`). Compress stroke `tpl\x00` and `RichTextDocument` payloads with `bv41`/`bv4-` + `bv4$`.
6. Write `index.notes.pb`, `index.search.pb` (may be empty if not pre-indexed), `document.info.pb` (0 bytes), and `schema.pb` (`{1: max_min_schema_version}`). Zip everything with DEFLATE (`ZIP_DEFLATED`).

### 6.3 Common Pitfalls & Gotchas Checklist

- **Forgetting `PageUUID + 1`**: Creating a random `NoteLayerUUID` unrelated to `PageUUID` breaks page-to-note-layer resolution.
- **Half-width vs Full-width**: Format 2 (`pen_type = 1`) stores `halfWidth` (`r`), while Formats 1 & 3 store `fullWidth` (`2r`).
- **Arc Sweep Inversion**: Treating Format 2 `clockwise == 1` as SVG `sweep-flag = 1` creates inverted caps/bowties in Y-down SVGs; use `sweep-flag = 0` for `clockwise == 1`.
- **Sticky Note Double-Offset Trap**: `tpl` points on child ink (`f7.100`) are already in page coordinates at creation time, and `f7.6 = -parent.origin`. Always compute `tpl + f7.6 + current_parent_origin`.
- **Length-Prefix vs Raw Protobuf**: `schema.pb`, `search/<NoteLayerUUID>`, and `RichTextDocument` are NOT length-prefixed; all `index.*.pb`, `notes/*`, and `search/<PdfUUID>` files ARE varint length-prefixed.
- **Tombstone `NaN` Rects**: Erased `ShapeFillItem` (`f9`) records store IEEE-754 `NaN` floats in `bounding_box`; sanitize before serializing strict JSON.
- **`proto3` Omitted Zeroes**: Default `0`/`0.0`/`""` fields are omitted on the wire (e.g., `ZOrder.index = 0`, `Point.x = 0.0`, `ColorRGBA.r/g/b = 0.0`, `LwwUint32` unset theme in scanned PDF templates).

---

## 7. Verification Matrix & Known Gaps

### 7.1 What Was 100% Byte-Verified on `Test.goodnotes`
- **Archive integrity**: 27/27 files parsed with 0 errors (`Test.goodnotes` SHA-256 unchanged).
- **UUID derivation**: 4/4 pages satisfy `UUID(page_id).int + 1 == UUID(note_layer_id).int`.
- **Note layer headers/revisions**: 173/173 objects (`155` active, `18` deleted) satisfy `header.revision == payload.revision` and `max(min_schema_version) == 35 == schema.pb`.
- **`tpl\x00` codec**: 157/157 TPL stroke payloads parsed with 0 leftover bytes and re-encoded **100% byte-for-byte identical** (`encode_tpl(*parse_tpl_raw(raw)) == raw`).
- **Apple `COMPRESSION_LZ4` (`bv41`)**: 162/162 compressed blobs (157 strokes + 5 RichText documents) round-tripped **100% identically** in pure Python AND were verified **100% byte-identical** by macOS `/usr/lib/libcompression.dylib` (`COMPRESSION_LZ4 = 0x100`).
- **Visual SVG reconstruction**: Pages 1, 2, and 3 rendered cleanly via `goodnotes_codec.py render-svg` and visually verified via rasterized previews.
- **Synthetic Writer**: `GoodnotesBuilder` generated a valid schema-v35 `.goodnotes` archive containing all primary object types and passed full re-parse verification.

### 7.2 Known Gaps & Unobserved Features (Transparent Limitations)
1. **8-byte `RichTextContent.content_hash` (`f20.31.1.3` / `f21.32.1.3`)**: Deterministic across identical payloads (all 3 empty flowchart nodes emit `8ae34cef4788ecae`), but does not match unseeded SHA-256[:8], MD5[:8], SHA-1[:8], FNV-1a-64, DJB2-64, or seed-0 xxHash64 of compressed or decompressed bytes. Likely uses a seeded non-cryptographic 64-bit hash (e.g., `xxHash64` with non-zero seed, MurmurHash3, or Swift `Hasher` / internal struct hash). Our writer currently emits `sha256[:8]` as a deterministic 8-byte placeholder; Goodnotes' tolerance of placeholder hashes on import has not been tested on-device.
2. **Pencil `paramA` / `paramB` (`Format 3`)**: Confirmed as batch-constant `float32` values per stroke batch (likely stylus altitude/azimuth/shading state at stroke capture), exact formula unverified without Goodnotes binary disassembly.
3. **`NoteObjectHeader.const_5381` (`hdr.14`)**: Observed as `5381` on every note object in `Test.goodnotes`; exact semantic purpose (format constant / default hash seed / compatibility tag) is unknown beyond its constant value.
4. **RichText `CharStyle.60` / `CharStyle.70`**: Observed as `-60` / `-20.0` in `DefaultCharStyle` and `-404` / `-404.0` ("inherit") in `TextRun.CharStyle` (likely paragraph spacing or baseline/tracking metrics).
5. **Unobserved Goodnotes Features**: Features not used in `Test.goodnotes` (e.g., audio recordings, Study Sets / flashcards, PDF bookmarks/outlines, comments/collaboration threads, laser pointer ephemeral data, math conversion / handwriting-to-text, equation objects) do not appear in this specimen and would require inspecting a `.goodnotes` file containing them.
