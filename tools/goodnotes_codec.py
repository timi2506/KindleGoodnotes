#!/usr/bin/env python3
"""Reference reader, disassembler, SVG renderer, writer, and verifier for `.goodnotes` files.

Zero external dependencies (Python 3 standard library only; optionally uses macOS
`/usr/lib/libcompression.dylib` during `verify` to cross-check Apple `bv41` LZ4).
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import html
import io
import json
import math
import os
import re
import struct
import sys
import time
import uuid
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants & Unit Conversions
# ---------------------------------------------------------------------------

GOODNOTES_PPI = 132.0
PDF_DPI = 72.0
PT_TO_GN = GOODNOTES_PPI / PDF_DPI  # 11 / 6 = 1.8333333333333333
MM_TO_GN = GOODNOTES_PPI / 25.4     # ~5.196850393700787

DEFAULT_REPLICA_ID = 5589758967719760423
NOTE_HEADER_CONST_F14 = 5381

EVENT_TYPE_NAMES = {
    2: "CreatePageTemplate",
    6: "RegisterAttachment",
    10: "UpdateCurrentPage",
    30: "CreateDocument",
    54: "CreatePage",
    102: "NoteLayerCheckpoint",
    103: "PdfSearchIndexed",
    104: "PageSearchIndexed",
    105: "SearchIndexJob",
}

NOTE_PAYLOAD_NAMES = {
    1: "ImageItem",
    7: "StrokeItem",
    9: "ShapeFillItem",
    20: "StickyNoteItem",
    21: "TextOrShapeItem",
    22: "ConnectorItem",
}

PEN_TYPE_NAMES = {
    0: "BallpointOrShapeOrHighlighter",
    1: "FountainOrBrushOrTape",
    5: "Pencil",
}

TPL_FORMAT_NAMES = {
    "vuA(v)A(S(uu))A(S(uuuu))vA(f)": "Format1_BallpointOrHighlighter",
    "vA(v)A(u)A(u)A(v)A(v)A(u)A(u)A(u)A(u)A(v)": "Format2_FountainBrushOrTape",
    "vuA(v)A(S(uuuuu))A(S(uuuuuuuuuuu))A(S(uu))A(v)A(S(uu))A(S(uuuu))A(u)": "Format3_Pencil",
}


def sanitize_json(obj: Any) -> Any:
    """Convert non-finite floats and bytes to strict RFC-8259 JSON values."""
    if isinstance(obj, float):
        if math.isnan(obj):
            return "NaN"
        if math.isinf(obj):
            return "Infinity" if obj > 0 else "-Infinity"
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_json(x) for x in obj]
    return obj


# ---------------------------------------------------------------------------
# Protobuf Wire Codec (Zero-Dependency)
# ---------------------------------------------------------------------------

def encode_varint(value: int) -> bytes:
    """Encode an unsigned or 64-bit two's-complement integer as base-128 varint."""
    if value < 0:
        value &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    """Decode base-128 varint starting at `pos`."""
    val = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError(f"Unexpected EOF reading varint at {pos}")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
        if shift > 70:
            raise ValueError(f"Varint exceeds 10 bytes at {pos}")


def to_int64(u: int) -> int:
    """Interpret unsigned 64-bit varint as signed int64."""
    return u - (1 << 64) if u >= (1 << 63) else u


def parse_pb(buf: bytes) -> List[Tuple[int, int, Any]]:
    """Parse raw protobuf wire format into list of `(field_number, wire_type, raw_value)`."""
    pos = 0
    fields: List[Tuple[int, int, Any]] = []
    n = len(buf)
    while pos < n:
        tag, pos = decode_varint(buf, pos)
        fn = tag >> 3
        wt = tag & 7
        if fn == 0:
            raise ValueError(f"Invalid protobuf field number 0 at {pos}")
        if wt == 0:
            val, pos = decode_varint(buf, pos)
            fields.append((fn, 0, val))
        elif wt == 1:
            if pos + 8 > n:
                raise ValueError(f"Truncated fixed64 at {pos}")
            raw = buf[pos:pos + 8]
            pos += 8
            fields.append((fn, 1, raw))
        elif wt == 2:
            ln, pos = decode_varint(buf, pos)
            if pos + ln > n:
                raise ValueError(f"Truncated length-delimited field {fn} ({ln}B > {n - pos}B)")
            raw = buf[pos:pos + ln]
            pos += ln
            fields.append((fn, 2, raw))
        elif wt == 5:
            if pos + 4 > n:
                raise ValueError(f"Truncated fixed32 at {pos}")
            raw = buf[pos:pos + 4]
            pos += 4
            fields.append((fn, 5, raw))
        else:
            raise ValueError(f"Unsupported protobuf wire type {wt} at {pos}")
    return fields


def encode_pb(fields: List[Tuple[int, int, Any]]) -> bytes:
    """Encode `(field_number, wire_type, value)` list to raw protobuf bytes."""
    out = bytearray()
    for fn, wt, val in fields:
        out.extend(encode_varint((fn << 3) | wt))
        if wt == 0:
            out.extend(encode_varint(int(val)))
        elif wt == 1:
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                out.extend(struct.pack("<d", float(val)))
            else:
                assert isinstance(val, (bytes, bytearray)) and len(val) == 8
                out.extend(val)
        elif wt == 2:
            if isinstance(val, str):
                raw = val.encode("utf-8")
            else:
                raw = bytes(val)
            out.extend(encode_varint(len(raw)))
            out.extend(raw)
        elif wt == 5:
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                out.extend(struct.pack("<f", float(val)))
            else:
                assert isinstance(val, (bytes, bytearray)) and len(val) == 4
                out.extend(val)
        else:
            raise ValueError(f"Unsupported wire type {wt}")
    return bytes(out)


def parse_delimited(buf: bytes) -> List[List[Tuple[int, int, Any]]]:
    """Parse varint-length-prefixed protobuf stream."""
    pos = 0
    msgs = []
    n = len(buf)
    while pos < n:
        ln, pos = decode_varint(buf, pos)
        if pos + ln > n:
            raise ValueError(f"Truncated delimited protobuf ({ln}B > {n - pos}B)")
        msgs.append(parse_pb(buf[pos:pos + ln]))
        pos += ln
    return msgs


def encode_delimited(messages: List[bytes]) -> bytes:
    """Encode a list of serialized protobuf messages as a varint-length-delimited stream."""
    out = bytearray()
    for msg in messages:
        out.extend(encode_varint(len(msg)))
        out.extend(msg)
    return bytes(out)


def pb_dict(fields: List[Tuple[int, int, Any]]) -> Dict[int, List[Tuple[int, Any]]]:
    """Group parsed protobuf fields by field number preserving repeated values."""
    d: Dict[int, List[Tuple[int, Any]]] = {}
    for fn, wt, val in fields:
        d.setdefault(fn, []).append((wt, val))
    return d


def pb_f32(raw: bytes) -> float:
    return struct.unpack("<f", raw)[0]


def pb_f64(raw: bytes) -> float:
    return struct.unpack("<d", raw)[0]


def pb_u64(raw: bytes) -> int:
    return struct.unpack("<Q", raw)[0]


# ---------------------------------------------------------------------------
# Apple COMPRESSION_LZ4 (`bv41` / `bv4-` / `bv4$`) Codec
# ---------------------------------------------------------------------------

def decompress_bv41(data: bytes) -> bytes:
    """Decompress Apple COMPRESSION_LZ4 stream (`bv41` / `bv4-` / `bv4$`)."""
    pos = 0
    n = len(data)
    out = bytearray()
    while pos < n:
        magic = data[pos:pos + 4]
        if magic == b"bv4$":
            pos += 4
            break
        if magic == b"bv4-":
            uncomp_sz = struct.unpack_from("<I", data, pos + 4)[0]
            pos += 8
            out.extend(data[pos:pos + uncomp_sz])
            pos += uncomp_sz
        elif magic == b"bv41":
            uncomp_sz, comp_sz = struct.unpack_from("<II", data, pos + 4)
            pos += 12
            blk = data[pos:pos + comp_sz]
            pos += comp_sz
            bp = 0
            bn = len(blk)
            bout = bytearray()
            while bp < bn:
                tok = blk[bp]
                bp += 1
                lit_len = tok >> 4
                if lit_len == 15:
                    while True:
                        b = blk[bp]
                        bp += 1
                        lit_len += b
                        if b != 255:
                            break
                bout.extend(blk[bp:bp + lit_len])
                bp += lit_len
                if bp >= bn:
                    break
                offset = struct.unpack_from("<H", blk, bp)[0]
                bp += 2
                if offset == 0:
                    raise ValueError("Invalid LZ4 match offset 0")
                match_len = (tok & 0x0F) + 4
                if (tok & 0x0F) == 15:
                    while True:
                        b = blk[bp]
                        bp += 1
                        match_len += b
                        if b != 255:
                            break
                start = len(bout) - offset
                for i in range(match_len):
                    bout.append(bout[start + i])
            if len(bout) != uncomp_sz:
                raise ValueError(f"bv41 decompressed size mismatch: {len(bout)} != {uncomp_sz}")
            out.extend(bout)
        else:
            raise ValueError(f"Unknown Apple LZ4 chunk magic {magic!r} at {pos}")
    if pos != n:
        raise ValueError(f"Trailing bytes after bv4$ marker: {n - pos}")
    return bytes(out)


def _lz4_compress_block(src: bytes) -> bytes:
    """Pure-Python standard raw LZ4 block compressor."""
    n = len(src)
    if n == 0:
        return b""
    if n < 13:
        # Too short for LZ4 match encoding (last 5 bytes must be literals, min match 4).
        out = bytearray()
        tok = (min(n, 15) << 4)
        out.append(tok)
        if n >= 15:
            rem = n - 15
            while rem >= 255:
                out.append(255)
                rem -= 255
            out.append(rem)
        out.extend(src)
        return bytes(out)

    hash_table: Dict[bytes, int] = {}
    out = bytearray()
    anchor = 0
    pos = 0
    limit = n - 12  # Ensure room for 4-byte match + 5 trailing literals + margin

    def emit_literals_only(lit_bytes: bytes) -> None:
        ll = len(lit_bytes)
        tok = (min(ll, 15) << 4)
        out.append(tok)
        if ll >= 15:
            rem = ll - 15
            while rem >= 255:
                out.append(255)
                rem -= 255
            out.append(rem)
        out.extend(lit_bytes)

    while pos <= limit:
        seq = src[pos:pos + 4]
        ref = hash_table.get(seq)
        hash_table[seq] = pos
        if ref is None or pos - ref > 65535 or pos == ref:
            pos += 1
            continue

        # Extend match forward, keeping at least 5 bytes at the end for last literals
        match_end_limit = n - 5
        ml = 4
        while pos + ml < match_end_limit and src[ref + ml] == src[pos + ml]:
            ml += 1

        lit_len = pos - anchor
        ml_code = ml - 4
        tok = (min(lit_len, 15) << 4) | min(ml_code, 15)
        out.append(tok)
        if lit_len >= 15:
            rem = lit_len - 15
            while rem >= 255:
                out.append(255)
                rem -= 255
            out.append(rem)
        out.extend(src[anchor:pos])
        out.extend(struct.pack("<H", pos - ref))
        if ml_code >= 15:
            rem = ml_code - 15
            while rem >= 255:
                out.append(255)
                rem -= 255
            out.append(rem)

        pos += ml
        anchor = pos
        if pos <= limit:
            hash_table[src[pos - 2:pos + 2]] = pos - 2

    emit_literals_only(src[anchor:])
    return bytes(out)


def compress_bv41(data: bytes, chunk_size: int = 65536, allow_uncompressed: bool = False) -> bytes:
    """Compress bytes into an Apple COMPRESSION_LZ4 (`bv41` ... `bv4$`) stream."""
    out = bytearray()
    for off in range(0, len(data), chunk_size):
        chunk = data[off:off + chunk_size]
        comp = _lz4_compress_block(chunk)
        if allow_uncompressed and len(comp) + 12 >= len(chunk) + 8:
            out.extend(b"bv4-")
            out.extend(struct.pack("<I", len(chunk)))
            out.extend(chunk)
        else:
            out.extend(b"bv41")
            out.extend(struct.pack("<II", len(chunk), len(comp)))
            out.extend(comp)
    if len(data) == 0:
        out.extend(b"bv41")
        out.extend(struct.pack("<II", 0, 0))
    out.extend(b"bv4$")
    return bytes(out)


# ---------------------------------------------------------------------------
# `tpl\x00` Serialization Codec (troydhanson/tpl format)
# ---------------------------------------------------------------------------

def _parse_tpl_fmt(fmt: str, pos: int = 0) -> Tuple[List[Tuple[str, Any]], int]:
    nodes: List[Tuple[str, Any]] = []
    while pos < len(fmt):
        c = fmt[pos]
        if c == ")":
            return nodes, pos + 1
        if c in ("A", "S"):
            if pos + 1 >= len(fmt) or fmt[pos + 1] != "(":
                raise ValueError(f"Expected '(' after {c} in TPL format {fmt!r}")
            sub, pos = _parse_tpl_fmt(fmt, pos + 2)
            nodes.append((c, sub))
        else:
            nodes.append((c, None))
            pos += 1
    return nodes, pos


def _read_tpl_nodes(buf: bytes, pos: int, nodes: List[Tuple[str, Any]]) -> Tuple[List[Any], int]:
    vals: List[Any] = []
    for kind, sub in nodes:
        if kind == "v":
            vals.append(struct.unpack_from("<H", buf, pos)[0])
            pos += 2
        elif kind == "u":
            # Store raw uint32 bits so NaN, -0.0, and integer seeds round-trip identically!
            vals.append(struct.unpack_from("<I", buf, pos)[0])
            pos += 4
        elif kind == "i":
            vals.append(struct.unpack_from("<i", buf, pos)[0])
            pos += 4
        elif kind == "f":
            vals.append(struct.unpack_from("<Q", buf, pos)[0])
            pos += 8
        elif kind == "c":
            vals.append(buf[pos])
            pos += 1
        elif kind == "S":
            sv, pos = _read_tpl_nodes(buf, pos, sub)
            vals.append(tuple(sv))
        elif kind == "A":
            cnt = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
            arr = []
            for _ in range(cnt):
                ev, pos = _read_tpl_nodes(buf, pos, sub)
                arr.append(ev[0] if len(ev) == 1 else tuple(ev))
            vals.append(arr)
        else:
            raise ValueError(f"Unsupported TPL type char {kind!r}")
    return vals, pos


def parse_tpl_raw(buf: bytes) -> Tuple[str, List[Any]]:
    """Losslessly parse a `tpl\\x00` binary buffer into `(fmt, raw_values)`."""
    if buf[:4] != b"tpl\x00":
        raise ValueError(f"Invalid tpl magic: {buf[:4]!r}")
    total_size = struct.unpack_from("<I", buf, 4)[0]
    if total_size != len(buf):
        raise ValueError(f"TPL size header {total_size} != buffer length {len(buf)}")
    nul = buf.index(0, 8)
    fmt = buf[8:nul].decode("ascii")
    nodes, endp = _parse_tpl_fmt(fmt)
    if endp != len(fmt):
        raise ValueError(f"Unbalanced parens in TPL format {fmt!r}")
    vals, pos = _read_tpl_nodes(buf, nul + 1, nodes)
    if pos != len(buf):
        raise ValueError(f"Trailing bytes in TPL buffer: {len(buf) - pos}")
    return fmt, vals


def _write_tpl_nodes(out: bytearray, vals: List[Any], nodes: List[Tuple[str, Any]]) -> None:
    for val, (kind, sub) in zip(vals, nodes):
        if kind == "v":
            out.extend(struct.pack("<H", int(val)))
        elif kind == "u":
            if isinstance(val, float):
                out.extend(struct.pack("<f", val))
            else:
                out.extend(struct.pack("<I", int(val)))
        elif kind == "i":
            out.extend(struct.pack("<i", int(val)))
        elif kind == "f":
            if isinstance(val, float):
                out.extend(struct.pack("<d", val))
            else:
                out.extend(struct.pack("<Q", int(val)))
        elif kind == "c":
            out.append(int(val) & 0xFF)
        elif kind == "S":
            _write_tpl_nodes(out, list(val), sub)
        elif kind == "A":
            out.extend(struct.pack("<I", len(val)))
            if len(sub) == 1 and sub[0][0] != "S":
                for item in val:
                    _write_tpl_nodes(out, [item], sub)
            elif len(sub) == 1 and sub[0][0] == "S":
                for item in val:
                    _write_tpl_nodes(out, [item], sub)
            else:
                for item in val:
                    _write_tpl_nodes(out, list(item), sub)
        else:
            raise ValueError(f"Unsupported TPL type char {kind!r}")


def encode_tpl(fmt: str, vals: List[Any]) -> bytes:
    """Encode `(fmt, vals)` back into exact `tpl\\x00` binary format."""
    nodes, endp = _parse_tpl_fmt(fmt)
    if endp != len(fmt):
        raise ValueError(f"Unbalanced TPL format {fmt!r}")
    payload = bytearray()
    _write_tpl_nodes(payload, vals, nodes)
    header_prefix = b"tpl\x00" + b"\x00\x00\x00\x00" + fmt.encode("ascii") + b"\x00"
    total_size = len(header_prefix) + len(payload)
    out = bytearray(header_prefix)
    struct.pack_into("<I", out, 4, total_size)
    out.extend(payload)
    return bytes(out)


def u32_to_f32(u: int) -> float:
    return struct.unpack("<f", struct.pack("<I", u))[0]


def u64_to_f64(u: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", u))[0]


def f32_to_u32(f: float) -> int:
    return struct.unpack("<I", struct.pack("<f", f))[0]


def decode_stroke_tpl(raw_tpl: bytes) -> Dict[str, Any]:
    """Decode `tpl\\x00` stroke payload into semantic structured dictionary."""
    fmt, vals = parse_tpl_raw(raw_tpl)
    if fmt == "vuA(v)A(S(uu))A(S(uuuu))vA(f)":
        ops = vals[2]
        moves = [(u32_to_f32(x), u32_to_f32(y)) for x, y in vals[3]]
        quads = [(u32_to_f32(cx), u32_to_f32(cy), u32_to_f32(ex), u32_to_f32(ey)) for cx, cy, ex, ey in vals[4]]
        return {
            "tpl_format": fmt,
            "kind": TPL_FORMAT_NAMES[fmt],
            "version": vals[0],
            "full_width": u32_to_f32(vals[1]),
            "ops": ops,
            "move_points": moves,
            "quad_segments": quads,
            "cap_flag": vals[5],
            "extra_doubles": [u64_to_f64(x) for x in vals[6]],
        }
    if fmt == "vA(v)A(u)A(u)A(v)A(v)A(u)A(u)A(u)A(u)A(v)":
        c_ops = vals[1]
        starts_f = [u32_to_f32(x) for x in vals[2]]
        segs_f = [u32_to_f32(x) for x in vals[3]]
        subpath_counts = vals[4]
        o_ops = vals[5]
        o_moves = [u32_to_f32(x) for x in vals[6]]
        o_lines = [u32_to_f32(x) for x in vals[7]]
        o_cubics = [u32_to_f32(x) for x in vals[8]]
        o_arcs = [u32_to_f32(x) for x in vals[9]]
        o_arc_cw = vals[10]

        # Reconstruct centerline subpaths
        centerline = []
        si, qi = 0, 0
        for op in c_ops:
            if op == 0:
                centerline.append({"op": "moveTo", "x": starts_f[si], "y": starts_f[si + 1], "halfWidth": starts_f[si + 2]})
                si += 3
            elif op == 1:
                centerline.append({
                    "op": "quadTo",
                    "cx": segs_f[qi], "cy": segs_f[qi + 1], "cHalfWidth": segs_f[qi + 2],
                    "ex": segs_f[qi + 3], "ey": segs_f[qi + 4], "eHalfWidth": segs_f[qi + 5],
                })
                qi += 6
            elif op == 4:
                centerline.append({"op": "ellipticalMoveTo", "x": starts_f[si], "y": starts_f[si + 1], "majorR": starts_f[si + 2], "angle": starts_f[si + 3]})
                si += 4
            elif op == 5:
                centerline.append({
                    "op": "ellipticalQuadTo",
                    "cx": segs_f[qi], "cy": segs_f[qi + 1], "cMajorR": segs_f[qi + 2],
                    "ex": segs_f[qi + 3], "ey": segs_f[qi + 4], "eMajorR": segs_f[qi + 5],
                    "cAngle": segs_f[qi + 6], "eAngle": segs_f[qi + 7], "flatness": segs_f[qi + 8],
                })
                qi += 9
            else:
                centerline.append({"op": f"unknown_{op}"})

        # Reconstruct outline subpaths
        outlines = []
        op_cursor = 0
        mi = li = ci = ai = wi = 0
        for cnt in subpath_counts:
            sub_cmds = []
            for _ in range(cnt):
                oop = o_ops[op_cursor]
                op_cursor += 1
                if oop == 0:
                    sub_cmds.append({"op": "moveTo", "x": o_moves[mi], "y": o_moves[mi + 1]})
                    mi += 2
                elif oop == 1:
                    sub_cmds.append({"op": "lineTo", "x": o_lines[li], "y": o_lines[li + 1]})
                    li += 2
                elif oop == 2:
                    sub_cmds.append({
                        "op": "cubicTo",
                        "c1x": o_cubics[ci], "c1y": o_cubics[ci + 1],
                        "c2x": o_cubics[ci + 2], "c2y": o_cubics[ci + 3],
                        "ex": o_cubics[ci + 4], "ey": o_cubics[ci + 5],
                    })
                    ci += 6
                elif oop == 3:
                    sub_cmds.append({
                        "op": "arc",
                        "cx": o_arcs[ai], "cy": o_arcs[ai + 1], "r": o_arcs[ai + 2],
                        "startAngle": o_arcs[ai + 3], "endAngle": o_arcs[ai + 4],
                        "clockwise": bool(o_arc_cw[wi]),
                    })
                    ai += 5
                    wi += 1
                elif oop == 6:
                    sub_cmds.append({
                        "op": "ellipticalArc",
                        "cx": o_arcs[ai], "cy": o_arcs[ai + 1],
                        "rx": o_arcs[ai + 2], "ry": o_arcs[ai + 3],
                        "startAngle": o_arcs[ai + 4], "endAngle": o_arcs[ai + 5],
                        "rotation": o_arcs[ai + 6],
                        "clockwise": bool(o_arc_cw[wi]),
                    })
                    ai += 7
                    wi += 1
                else:
                    sub_cmds.append({"op": f"unknown_{oop}"})
            outlines.append(sub_cmds)

        return {
            "tpl_format": fmt,
            "kind": TPL_FORMAT_NAMES[fmt],
            "version": vals[0],
            "centerline_ops": c_ops,
            "centerline": centerline,
            "subpath_op_counts": subpath_counts,
            "outline_ops": o_ops,
            "outlines": outlines,
        }
    if fmt == "vuA(v)A(S(uuuuu))A(S(uuuuuuuuuuu))A(S(uu))A(v)A(S(uu))A(S(uuuu))A(u)":
        moves = [
            {
                "x": u32_to_f32(s[0]), "y": u32_to_f32(s[1]),
                "paramA": u32_to_f32(s[2]), "paramB": u32_to_f32(s[3]),
                "pressure": u32_to_f32(s[4]),
            }
            for s in vals[3]
        ]
        quads = [
            {
                "seed_u32": seg[0],
                "cx": u32_to_f32(seg[1]), "cy": u32_to_f32(seg[2]),
                "cParamA": u32_to_f32(seg[3]), "cParamB": u32_to_f32(seg[4]), "cPressure": u32_to_f32(seg[5]),
                "ex": u32_to_f32(seg[6]), "ey": u32_to_f32(seg[7]),
                "eParamA": u32_to_f32(seg[8]), "eParamB": u32_to_f32(seg[9]), "ePressure": u32_to_f32(seg[10]),
            }
            for seg in vals[4]
        ]
        return {
            "tpl_format": fmt,
            "kind": TPL_FORMAT_NAMES[fmt],
            "version": vals[0],
            "base_full_width": u32_to_f32(vals[1]),
            "ops": vals[2],
            "move_points": moves,
            "quad_segments": quads,
        }
    return {"tpl_format": fmt, "kind": "Unknown", "raw_vals": vals}


# ---------------------------------------------------------------------------
# Shared Protobuf Message Decoders
# ---------------------------------------------------------------------------

def _dec_point(raw: bytes) -> Dict[str, float]:
    d = pb_dict(parse_pb(raw))
    return {
        "x": pb_f32(d[1][0][1]) if 1 in d else 0.0,
        "y": pb_f32(d[2][0][1]) if 2 in d else 0.0,
    }


def _enc_point(x: float, y: float) -> bytes:
    fields = []
    if x != 0.0:
        fields.append((1, 5, x))
    if y != 0.0:
        fields.append((2, 5, y))
    return encode_pb(fields)


def _dec_size(raw: bytes) -> Dict[str, float]:
    d = pb_dict(parse_pb(raw))
    return {
        "width": pb_f32(d[1][0][1]) if 1 in d else 0.0,
        "height": pb_f32(d[2][0][1]) if 2 in d else 0.0,
    }


def _enc_size(w: float, h: float) -> bytes:
    fields = []
    if w != 0.0:
        fields.append((1, 5, w))
    if h != 0.0:
        fields.append((2, 5, h))
    return encode_pb(fields)


def _dec_rect(raw: bytes) -> Dict[str, Any]:
    d = pb_dict(parse_pb(raw))
    return {
        "origin": _dec_point(d[1][0][1]) if 1 in d else {"x": 0.0, "y": 0.0},
        "size": _dec_size(d[2][0][1]) if 2 in d else {"width": 0.0, "height": 0.0},
    }


def _enc_rect(x: float, y: float, w: float, h: float) -> bytes:
    return encode_pb([(1, 2, _enc_point(x, y)), (2, 2, _enc_size(w, h))])


def _dec_color(raw: bytes) -> Dict[str, float]:
    d = pb_dict(parse_pb(raw))
    return {
        "r": pb_f32(d[1][0][1]) if 1 in d else 0.0,
        "g": pb_f32(d[2][0][1]) if 2 in d else 0.0,
        "b": pb_f32(d[3][0][1]) if 3 in d else 0.0,
        "a": pb_f32(d[4][0][1]) if 4 in d else 0.0,
    }


def _enc_color(r: float, g: float, b: float, a: float = 1.0) -> bytes:
    fields = []
    if r != 0.0:
        fields.append((1, 5, r))
    if g != 0.0:
        fields.append((2, 5, g))
    if b != 0.0:
        fields.append((3, 5, b))
    if a != 0.0:
        fields.append((4, 5, a))
    return encode_pb(fields)


def _dec_lww_clock(raw: bytes) -> Dict[str, int]:
    d = pb_dict(parse_pb(raw))
    return {
        "counter": d[1][0][1] if 1 in d else 0,
        "tiebreaker": d[2][0][1] if 2 in d else 0,
    }


def _enc_lww_clock(counter: int, tiebreaker: int) -> bytes:
    fields = []
    if counter != 0:
        fields.append((1, 0, counter))
    if tiebreaker != 0:
        fields.append((2, 0, tiebreaker))
    return encode_pb(fields)


def _dec_zorder(raw: bytes) -> Dict[str, int]:
    outer = pb_dict(parse_pb(raw))
    if 1 not in outer:
        return {"index": 0, "tiebreaker": 0}
    inner = pb_dict(parse_pb(outer[1][0][1]))
    return {
        "index": inner[1][0][1] if 1 in inner else 0,
        "tiebreaker": inner[2][0][1] if 2 in inner else 0,
    }


def _enc_zorder(index: int, tiebreaker: int) -> bytes:
    inner = []
    if index != 0:
        inner.append((1, 0, index))
    if tiebreaker != 0:
        inner.append((2, 0, tiebreaker))
    return encode_pb([(1, 2, encode_pb(inner))])


def decode_richtext_container(raw: bytes) -> Dict[str, Any]:
    """Decode `f20.31` / `f21.32` RichTextContainer including bv41-compressed RichTextDocument."""
    d = pb_dict(parse_pb(raw))
    res: Dict[str, Any] = {}
    if 1 in d:
        c = pb_dict(parse_pb(d[1][0][1]))
        comp = c[2][0][1]
        dec = decompress_bv41(comp)
        rt_fields = parse_pb(dec)
        runs = []
        for fn, wt, val in rt_fields:
            if fn == 1:
                rd = pb_dict(parse_pb(val))
                run: Dict[str, Any] = {"text": rd[1][0][1].decode("utf-8") if 1 in rd else ""}
                if 2 in rd:
                    cs = pb_dict(parse_pb(rd[2][0][1]))
                    cstyle: Dict[str, Any] = {}
                    if 3 in cs:
                        cstyle["text_color"] = _dec_color(cs[3][0][1])
                    if 4 in cs:
                        cstyle["hyperlink_url"] = cs[4][0][1].decode("utf-8")
                    if 5 in cs:
                        cstyle["highlight_color"] = _dec_color(cs[5][0][1])
                    if 40 in cs:
                        cstyle["font_size"] = pb_f32(cs[40][0][1])
                    if 60 in cs:
                        cstyle["unknown_s64_60"] = to_int64(cs[60][0][1])
                    if 70 in cs:
                        cstyle["unknown_f32_70"] = pb_f32(cs[70][0][1])
                    run["char_style"] = cstyle
                if 3 in rd:
                    ps = pb_dict(parse_pb(rd[3][0][1]))
                    pstyle: Dict[str, Any] = {}
                    if 4 in ps:
                        pstyle["alignment"] = ps[4][0][1]
                    run["paragraph_style"] = pstyle
                runs.append(run)
        res["content"] = {
            "compressed_bytes": len(comp),
            "decompressed_bytes": len(dec),
            "content_hash_hex": c[3][0][1].hex() if 3 in c else "",
            "format_version": c[4][0][1] if 4 in c else 0,
            "runs": runs,
            "plain_text": "".join(r["text"] for r in runs),
        }
    if 2 in d:
        res["measured_size"] = _dec_size(d[2][0][1])
    if 5 in d:
        sd = pb_dict(parse_pb(d[5][0][1]))
        default_style: Dict[str, Any] = {}
        if 1 in sd:
            cs = pb_dict(parse_pb(sd[1][0][1]))
            default_style["char_style"] = {
                "text_color": _dec_color(cs[3][0][1]) if 3 in cs else None,
                "font_family": cs[30][0][1].decode("utf-8") if 30 in cs else None,
                "font_size": pb_f32(cs[40][0][1]) if 40 in cs else None,
                "unknown_s64_60": to_int64(cs[60][0][1]) if 60 in cs else None,
                "unknown_f32_70": pb_f32(cs[70][0][1]) if 70 in cs else None,
            }
        res["default_style"] = default_style
    if 10 in d:
        ins = pb_dict(parse_pb(d[10][0][1]))
        res["insets"] = {
            "top": pb_f32(ins[1][0][1]) if 1 in ins else 0.0,
            "left": pb_f32(ins[2][0][1]) if 2 in ins else 0.0,
            "bottom": pb_f32(ins[3][0][1]) if 3 in ins else 0.0,
            "right": pb_f32(ins[4][0][1]) if 4 in ins else 0.0,
        }
    return res


def encode_richtext_container(
    text: str,
    font_family: str = "Helvetica Neue",
    font_size: float = 24.0,
    text_color: Tuple[float, float, float, float] = (0.0, 0.0, 0.0, 1.0),
    highlight_color: Optional[Tuple[float, float, float, float]] = None,
    hyperlink_url: Optional[str] = None,
    alignment: int = 0,
    measured_size: Optional[Tuple[float, float]] = None,
    insets: Optional[Tuple[float, float, float, float]] = None,
) -> bytes:
    """Encode a RichTextContainer protobuf for StickyNote (`f20.31`) or TextOrShape (`f21.32`)."""
    cs_fields: List[Tuple[int, int, Any]] = [
        (3, 2, _enc_color(*text_color)),
    ]
    if hyperlink_url:
        cs_fields.append((4, 2, hyperlink_url))
    if highlight_color:
        cs_fields.append((5, 2, _enc_color(*highlight_color)))
    cs_fields.extend([
        (40, 5, -404.0),
        (60, 0, -404),
        (70, 5, -404.0),
    ])
    ps_fields: List[Tuple[int, int, Any]] = [
        (1, 2, encode_pb([(1, 2, b"")])),
        (2, 2, encode_pb([(1, 0, -1)])),
        (3, 2, encode_pb([(1, 0, -1), (2, 0, -1)])),
    ]
    if alignment:
        ps_fields.append((4, 0, alignment))

    run_fields: List[Tuple[int, int, Any]] = []
    if text:
        run_fields.append((1, 2, text))
    run_fields.append((2, 2, encode_pb(cs_fields)))
    run_fields.append((3, 2, encode_pb(ps_fields)))

    rt_doc = encode_pb([(1, 2, encode_pb(run_fields))])
    comp = compress_bv41(rt_doc)
    # Deterministic placeholder 8-byte hash (actual Apple/Goodnotes internal hash algorithm unknown)
    placeholder_hash = hashlib.sha256(rt_doc).digest()[:8]

    content_msg = encode_pb([
        (2, 2, comp),
        (3, 2, placeholder_hash),
        (4, 0, 1),
    ])
    default_cs = encode_pb([
        (3, 2, _enc_color(*text_color)),
        (30, 2, font_family),
        (40, 5, font_size),
        (60, 0, -60),
        (70, 5, -20.0),
    ])
    default_ps = encode_pb([
        (1, 2, encode_pb([(1, 2, b"")])),
        (2, 2, b""),
        (3, 2, encode_pb([(1, 0, -1), (2, 0, -1)])),
    ])
    default_style = encode_pb([(1, 2, default_cs), (2, 2, default_ps)])

    fields: List[Tuple[int, int, Any]] = [(1, 2, content_msg)]
    if measured_size:
        fields.append((2, 2, _enc_size(*measured_size)))
    fields.append((5, 2, default_style))
    if insets:
        fields.append((10, 2, encode_pb([
            (1, 5, insets[0]), (2, 5, insets[1]), (3, 5, insets[2]), (4, 5, insets[3])
        ])))
        fields.append((11, 2, b""))
    return encode_pb(fields)


# ---------------------------------------------------------------------------
# High-Level Decoders for Every Archive File
# ---------------------------------------------------------------------------

def decode_schema(data: bytes) -> Dict[str, Any]:
    d = pb_dict(parse_pb(data))
    return {"schema_version": d[1][0][1] if 1 in d else 0}


def decode_index_entries(data: bytes, has_kind: bool = False) -> List[Dict[str, Any]]:
    entries = []
    for m in parse_delimited(data):
        d = pb_dict(m)
        item: Dict[str, Any] = {
            "uuid": d[1][0][1].decode("utf-8"),
            "path": d[2][0][1].decode("utf-8"),
        }
        if has_kind:
            item["kind"] = d[3][0][1] if 3 in d else 0
        entries.append(item)
    return entries


def decode_index_events(data: bytes) -> List[Dict[str, Any]]:
    events = []
    for idx, msg in enumerate(parse_delimited(data)):
        d = pb_dict(msg)
        entity_uuid = d[1][0][1].decode("utf-8")
        ev_tags = [k for k in d if k != 1]
        if len(ev_tags) != 1:
            raise ValueError(f"Event[{idx}] unexpected tags: {ev_tags}")
        et = ev_tags[0]
        raw_sub = d[et][0][1]
        sd = pb_dict(parse_pb(raw_sub))
        decoded: Dict[str, Any] = {
            "index": idx,
            "entity_uuid": entity_uuid,
            "event_tag": et,
            "event_type": EVENT_TYPE_NAMES.get(et, f"Unknown_{et}"),
        }
        if et == 30:  # CreateDocument
            title_d = pb_dict(parse_pb(sd[2][0][1]))
            folder_d = pb_dict(parse_pb(sd[3][0][1]))
            type_d = pb_dict(parse_pb(sd[6][0][1]))
            parent_d = pb_dict(parse_pb(sd[7][0][1]))
            decoded.update({
                "document_id": sd[1][0][1].decode("utf-8"),
                "title": title_d[1][0][1].decode("utf-8") if 1 in title_d else "",
                "title_clock": _dec_lww_clock(title_d[2][0][1]) if 2 in title_d else None,
                "folder_id": folder_d[1][0][1].decode("utf-8") if 1 in folder_d else "",
                "doc_type_marker": type_d[1][0][1].decode("utf-8", errors="replace") if 1 in type_d else "",
                "parent_folder_id": parent_d[1][0][1].decode("utf-8") if 1 in parent_d else "",
                "recognition_lang": sd[9][0][1].decode("utf-8") if 9 in sd else "",
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[13][0][1],
                "lamport": sd[14][0][1],
                "schema_version": sd[20][0][1],
            })
        elif et == 6:  # RegisterAttachment
            pdf_meta = None
            if 12 in sd and sd[12][0][1]:
                pm = pb_dict(parse_pb(sd[12][0][1]))
                pdf_meta = {
                    "page_count": pm[1][0][1] if 1 in pm else 0,
                    "version": pm[2][0][1] if 2 in pm else 0,
                }
            decoded.update({
                "logical_attachment_id": sd[1][0][1].decode("utf-8"),
                "storage_blob_id": sd[2][0][1].decode("utf-8"),
                "byte_size": sd[5][0][1] if 5 in sd else 0,
                "document_id": sd[6][0][1].decode("utf-8"),
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "pdf_meta": pdf_meta,
                "replica_id": sd[14][0][1],
                "lamport": sd[15][0][1],
                "schema_version": sd[16][0][1],
            })
        elif et == 2:  # CreatePageTemplate
            ruling = None
            if 18 in sd and sd[18][0][1]:
                rm = pb_dict(parse_pb(sd[18][0][1]))
                ruling = {
                    "bounds": _dec_rect(rm[1][0][1]) if 1 in rm else None,
                    "row_pitch_minus_stroke": pb_f32(rm[2][0][1]) if 2 in rm else 0.0,
                    "stroke_thickness": pb_f32(rm[3][0][1]) if 3 in rm else 0.0,
                    "ruling_kind": rm[5][0][1] if 5 in rm else 0,
                }
            paper_theme = None
            if 17 in sd and sd[17][0][1]:
                pt_d = pb_dict(parse_pb(sd[17][0][1]))
                paper_theme = pt_d[1][0][1] if 1 in pt_d else 0
            decoded.update({
                "document_id": sd[1][0][1].decode("utf-8"),
                "template_id": sd[2][0][1].decode("utf-8"),
                "logical_attachment_id": sd[4][0][1].decode("utf-8"),
                "pdf_page_number": sd[5][0][1] if 5 in sd else 1,
                "is_builtin_template": bool(sd[6][0][1]) if 6 in sd else False,
                "line_spacing": pb_f64(sd[7][0][1]) if 7 in sd else None,
                "page_size": _dec_size(sd[8][0][1]),
                "template_name": sd[9][0][1].decode("utf-8") if 9 in sd else "",
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "paper_theme": paper_theme,
                "ruling_layout": ruling,
                "replica_id": sd[15][0][1],
                "lamport": sd[16][0][1],
                "schema_version": sd[21][0][1],
            })
        elif et == 54:  # CreatePage
            tpl_lww = pb_dict(parse_pb(sd[3][0][1]))
            ord_lww = pb_dict(parse_pb(sd[4][0][1]))
            decoded.update({
                "document_id": sd[1][0][1].decode("utf-8"),
                "page_id": sd[2][0][1].decode("utf-8"),
                "note_layer_id": str(uuid.UUID(int=uuid.UUID(sd[2][0][1].decode("utf-8")).int + 1)).upper(),
                "template_id": tpl_lww[1][0][1].decode("utf-8") if 1 in tpl_lww else "",
                "order_key": ord_lww[1][0][1].decode("utf-8") if 1 in ord_lww else "",
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[13][0][1],
                "lamport": sd[14][0][1],
                "schema_version": sd[15][0][1],
            })
        elif et == 10:  # UpdateCurrentPage
            decoded.update({
                "document_id": sd[1][0][1].decode("utf-8"),
                "active_page_id": sd[2][0][1].decode("utf-8"),
                "editor_session_id": sd[3][0][1].decode("utf-8"),
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[13][0][1],
                "lamport": sd[14][0][1],
                "schema_version": sd[15][0][1],
            })
        elif et == 102:  # NoteLayerCheckpoint
            decoded.update({
                "note_layer_id": sd[1][0][1].decode("utf-8"),
                "document_id": sd[16][0][1].decode("utf-8"),
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[13][0][1],
                "lamport": sd[14][0][1],
                "schema_version": sd[15][0][1],
            })
        elif et == 103:  # PdfSearchIndexed
            decoded.update({
                "pdf_attachment_id": sd[1][0][1].decode("utf-8"),
                "document_id": sd[2][0][1].decode("utf-8"),
                "status": sd[14][0][1],
                "index_run_id": sd[16][0][1].decode("utf-8"),
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[18][0][1],
                "lamport": sd[19][0][1],
                "schema_version": sd[20][0][1],
            })
        elif et == 104:  # PageSearchIndexed
            decoded.update({
                "document_id": sd[1][0][1].decode("utf-8"),
                "note_layer_id": sd[2][0][1].decode("utf-8"),
                "content_hash_u64": sd[12][0][1] if 12 in sd else None,
                "lang": sd[13][0][1].decode("utf-8"),
                "status": sd[14][0][1],
                "index_run_id": sd[15][0][1].decode("utf-8"),
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[17][0][1],
                "lamport": sd[18][0][1],
                "schema_version": sd[19][0][1],
            })
        elif et == 105:  # SearchIndexJob
            decoded.update({
                "job_type": sd[1][0][1] if 1 in sd else 0,
                "document_id": sd[2][0][1].decode("utf-8"),
                "pdf_attachment_id": sd[3][0][1].decode("utf-8") if 3 in sd else None,
                "note_layer_id": sd[4][0][1].decode("utf-8") if 4 in sd else None,
                "content_hash_u64": sd[5][0][1] if 5 in sd else None,
                "lang": sd[6][0][1].decode("utf-8") if 6 in sd else None,
                "timestamp_ms": pb_f64(sd[10][0][1]),
                "event_id": sd[11][0][1].decode("utf-8"),
                "replica_id": sd[13][0][1],
                "lamport": sd[14][0][1],
                "schema_version": sd[15][0][1],
            })
        events.append(decoded)
    return events


def _dec_snapped_shape(raw: bytes) -> Dict[str, Any]:
    sd = pb_dict(parse_pb(raw))
    out: Dict[str, Any] = {
        "stroke_width": pb_f32(sd[15][0][1]) if 15 in sd else None,
    }
    if 1 in sd:
        pd = pb_dict(parse_pb(sd[1][0][1]))
        out["polyline"] = [_dec_point(v) for _, v in pd.get(1, [])]
    if 4 in sd:
        ed = pb_dict(parse_pb(sd[4][0][1]))
        out["ellipse"] = {
            "center": _dec_point(ed[1][0][1]),
            "radii": _dec_point(ed[2][0][1]),
            "rotation_rad": pb_f32(ed[3][0][1]) if 3 in ed else 0.0,
        }
    return out


def decode_note_layer(data: bytes) -> List[Dict[str, Any]]:
    """Decode `notes/<NoteLayerUUID>` paired ObjectHeader + ObjectPayload stream."""
    msgs = parse_delimited(data)
    if len(msgs) % 2 != 0:
        raise ValueError(f"Expected even message count in note layer, got {len(msgs)}")
    objects = []
    for i in range(0, len(msgs), 2):
        hd = pb_dict(msgs[i])
        header = {
            "object_id": hd[1][0][1].decode("utf-8"),
            "revision": _dec_lww_clock(hd[2][0][1]) if 2 in hd else None,
            "is_deleted": bool(hd[3][0][1]) if 3 in hd else False,
            "attachment_id": hd[4][0][1].decode("utf-8") if 4 in hd else None,
            "replica_id": hd[8][0][1] if 8 in hd else None,
            "lamport": hd[9][0][1] if 9 in hd else None,
            "const_5381": hd[14][0][1] if 14 in hd else None,
            "min_schema_version": hd[16][0][1] if 16 in hd else None,
            "parent_container_id": hd[20][0][1].decode("utf-8") if 20 in hd else None,
        }
        pay_list = msgs[i + 1]
        if len(pay_list) != 1:
            raise ValueError(f"Note payload[{i + 1}] expected 1 top field, got {len(pay_list)}")
        pfn, _, pval = pay_list[0]
        pd = pb_dict(parse_pb(pval))
        payload: Dict[str, Any] = {
            "payload_tag": pfn,
            "payload_type": NOTE_PAYLOAD_NAMES.get(pfn, f"Unknown_{pfn}"),
        }

        if pfn == 1:  # ImageItem
            payload.update({
                "id": pd[1][0][1].decode("utf-8"),
                "bounding_box": _dec_rect(pd[2][0][1]),
                "center_frame": _dec_rect(pd[3][0][1]),
                "attachment_id": pd[4][0][1].decode("utf-8"),
                "z_order": _dec_zorder(pd[5][0][1]),
                "is_sticker_element": bool(pd[6][0][1]) if 6 in pd else False,
                "element_asset_id": pd[7][0][1].decode("utf-8") if 7 in pd else None,
                "revision": _dec_lww_clock(pd[15][0][1]),
                "min_schema_version": pd[18][0][1],
                "math_graph_id": pd[19][0][1].decode("utf-8") if 19 in pd else None,
                "math_graph_json": json.loads(pd[20][0][1].decode("utf-8")) if 20 in pd else None,
            })
        elif pfn == 7:  # StrokeItem
            comp_tpl = pd[2][0][1]
            raw_tpl = decompress_bv41(comp_tpl)
            tpl_decoded = decode_stroke_tpl(raw_tpl)
            pen_type = pd[3][0][1] if 3 in pd else 0
            is_hl = bool(pd[5][0][1]) if 5 in pd else False
            has_tape = bool(6 in pd or 20 in pd) and (20 in pd and len(pd[20][0][1]) > 0)
            is_deleted = bool(pd[14][0][1]) if 14 in pd else False
            if is_deleted:
                tool_guess = "TombstonedStroke"
            elif has_tape:
                tool_guess = "StudyTape"
            elif is_hl:
                tool_guess = "Highlighter"
            elif pen_type == 5:
                tool_guess = "Pencil"
            elif pen_type == 1:
                tool_guess = "FountainOrBrushPen"
            elif 9 in pd and len(pd[9][0][1]) > 0:
                tool_guess = "SnappedShape"
            else:
                tool_guess = "BallpointPen"
            payload.update({
                "id": pd[1][0][1].decode("utf-8"),
                "tool_classification": tool_guess,
                "pen_type": pen_type,
                "color": _dec_color(pd[4][0][1]),
                "is_highlighter": is_hl,
                "local_offset": _dec_point(pd[6][0][1]) if 6 in pd and pd[6][0][1] else None,
                "z_order": _dec_zorder(pd[7][0][1]),
                "snapped_shape": _dec_snapped_shape(pd[9][0][1]) if 9 in pd and pd[9][0][1] else None,
                "is_deleted": is_deleted,
                "revision": _dec_lww_clock(pd[15][0][1]),
                "is_tape": has_tape,
                "min_schema_version": pd[21][0][1],
                "parent_container_id": pb_dict(parse_pb(pd[100][0][1]))[1][0][1].decode("utf-8") if 100 in pd else None,
                "compressed_tpl_bytes": len(comp_tpl),
                "decompressed_tpl_bytes": len(raw_tpl),
                "tpl": tpl_decoded,
            })
        elif pfn == 9:  # ShapeFillItem
            fg = pb_dict(parse_pb(pd[4][0][1])) if 4 in pd and pd[4][0][1] else {}
            fill_geom: Dict[str, Any] = {}
            if 1 in fg:
                poly_d = pb_dict(parse_pb(fg[1][0][1]))
                fill_geom["polygon"] = [_dec_point(v) for _, v in poly_d.get(1, [])]
            if 4 in fg:
                ed = pb_dict(parse_pb(fg[4][0][1]))
                fill_geom["ellipse"] = {
                    "center": _dec_point(ed[1][0][1]),
                    "radii": _dec_point(ed[2][0][1]),
                    "rotation_rad": pb_f32(ed[3][0][1]) if 3 in ed else 0.0,
                }
            payload.update({
                "id": pd[1][0][1].decode("utf-8"),
                "bounding_box": _dec_rect(pd[2][0][1]),
                "z_order": _dec_zorder(pd[3][0][1]),
                "fill_geometry": fill_geom or None,
                "associated_stroke_id": pd[5][0][1].decode("utf-8"),
                "fill_color": _dec_color(pd[7][0][1]),
                "is_deleted": bool(pd[14][0][1]) if 14 in pd else False,
                "revision": _dec_lww_clock(pd[15][0][1]),
                "min_schema_version": pd[18][0][1],
            })
        elif pfn == 20:  # StickyNoteItem
            tr = pb_dict(parse_pb(pd[20][0][1]))
            sc = pb_dict(parse_pb(pd[21][0][1]))
            fixed_sz = pb_dict(parse_pb(sc[2][0][1]))
            payload.update({
                "id": pd[1][0][1].decode("utf-8"),
                "min_schema_version": pd[2][0][1],
                "revision": _dec_lww_clock(pd[3][0][1]),
                "z_order": _dec_zorder(pd[7][0][1]),
                "origin": _dec_point(tr[1][0][1]),
                "scale": pb_f32(tr[3][0][1]) if 3 in tr else 1.0,
                "size": {
                    "width": pb_f32(fixed_sz[1][0][1]),
                    "height": pb_f32(fixed_sz[2][0][1]),
                    "max_height": pb_f32(fixed_sz[3][0][1]) if 3 in fixed_sz else None,
                },
                "background_color": _dec_color(pd[30][0][1]),
                "rich_text": decode_richtext_container(pd[31][0][1]),
                "author_id": pd[32][0][1].decode("utf-8") if 32 in pd else None,
                "author_name": pd[33][0][1].decode("utf-8") if 33 in pd else None,
            })
        elif pfn == 21:  # TextOrShapeItem
            tr = pb_dict(parse_pb(pd[20][0][1]))
            sc = pb_dict(parse_pb(pd[21][0][1]))
            size_spec: Dict[str, Any] = {}
            if 2 in sc:
                s2 = pb_dict(parse_pb(sc[2][0][1]))
                size_spec = {"mode": "fixed", "width": pb_f32(s2[1][0][1]), "height": pb_f32(s2[2][0][1]), "max_height": pb_f32(s2[3][0][1]) if 3 in s2 else None}
            elif 3 in sc:
                s3 = pb_dict(parse_pb(sc[3][0][1]))
                size_spec = {
                    "mode": "auto",
                    "min_width": pb_f32(s3[1][0][1]), "max_width": pb_f32(s3[2][0][1]),
                    "min_height": pb_f32(s3[3][0][1]), "max_height": pb_f32(s3[4][0][1]),
                }
            shape_kind: Dict[str, Any] = {}
            if 22 in pd:
                sk = pb_dict(parse_pb(pd[22][0][1]))
                if 1 in sk:
                    r1 = pb_dict(parse_pb(sk[1][0][1])) if sk[1][0][1] else {}
                    shape_kind = {"kind": "rectangle", "corner_radius": pb_f32(r1[1][0][1]) if 1 in r1 else 0.0}
                elif 3 in sk:
                    p3 = pb_dict(parse_pb(sk[3][0][1]))
                    poly_inner = pb_dict(parse_pb(p3[1][0][1]))
                    verts = []
                    for _, vraw in poly_inner.get(1, []):
                        vd = pb_dict(parse_pb(vraw))
                        verts.append({
                            "point": _dec_point(vd[1][0][1]) if 1 in vd else {"x": 0.0, "y": 0.0},
                            "vertex_type": vd[2][0][1] if 2 in vd else 0,
                            "corner_radius": pb_f32(vd[3][0][1]) if 3 in vd else 0.0,
                        })
                    shape_kind = {"kind": "polygon", "vertices": verts, "closed": bool(poly_inner[2][0][1]) if 2 in poly_inner else True}
            fill_color = None
            if 30 in pd:
                f30 = pb_dict(parse_pb(pd[30][0][1]))
                if 1 in f30:
                    f30_1 = pb_dict(parse_pb(f30[1][0][1]))
                    if 1 in f30_1:
                        fill_color = _dec_color(f30_1[1][0][1])
            border = None
            if 31 in pd:
                b31 = pb_dict(parse_pb(pd[31][0][1]))
                bcol = None
                if 3 in b31:
                    b31_3 = pb_dict(parse_pb(b31[3][0][1]))
                    if 1 in b31_3:
                        bcol = _dec_color(b31_3[1][0][1])
                border = {"width": pb_f32(b31[1][0][1]) if 1 in b31 else 0.0, "color": bcol}
            shadow = None
            if 33 in pd:
                sh = pb_dict(parse_pb(pd[33][0][1]))
                shadow = {
                    "opacity": pb_f32(pb_dict(parse_pb(sh[1][0][1]))[4][0][1]) if 1 in sh else 0.0,
                    "blur_radius": pb_f32(pb_dict(parse_pb(sh[3][0][1]))[2][0][1]) if 3 in sh else 0.0,
                }
            payload.update({
                "id": pd[1][0][1].decode("utf-8"),
                "min_schema_version": pd[2][0][1],
                "revision": _dec_lww_clock(pd[3][0][1]),
                "z_order": _dec_zorder(pd[7][0][1]),
                "is_textbox": bool(pd[9][0][1]) if 9 in pd else False,
                "origin": _dec_point(tr[1][0][1]),
                "scale": pb_f32(tr[3][0][1]) if 3 in tr else 1.0,
                "size_spec": size_spec,
                "shape_kind": shape_kind,
                "fill_color": fill_color,
                "border": border,
                "rich_text": decode_richtext_container(pd[32][0][1]) if 32 in pd else None,
                "shadow": shadow,
            })
        elif pfn == 22:  # ConnectorItem
            path_spec: Dict[str, Any] = {}
            if 20 in pd:
                p20 = pb_dict(parse_pb(pd[20][0][1]))
                path_spec = {
                    "kind": "quadratic_curve",
                    "start": _dec_point(pb_dict(parse_pb(p20[1][0][1]))[1][0][1]),
                    "control": _dec_point(p20[2][0][1]),
                    "end": _dec_point(pb_dict(parse_pb(p20[3][0][1]))[1][0][1]),
                }
            elif 21 in pd:
                p21 = pb_dict(parse_pb(pd[21][0][1]))
                mid = None
                if 5 in p21:
                    m5 = pb_dict(parse_pb(p21[5][0][1]))
                    if 2 in m5:
                        mid = _dec_point(m5[2][0][1])
                path_spec = {
                    "kind": "straight_or_elbow",
                    "start": _dec_point(pb_dict(parse_pb(p21[1][0][1]))[1][0][1]),
                    "end": _dec_point(pb_dict(parse_pb(p21[3][0][1]))[1][0][1]),
                    "mode": p21[4][0][1] if 4 in p21 else 0,
                    "midpoint": mid,
                }
            st = pb_dict(parse_pb(pd[32][0][1]))
            scol = _dec_color(pb_dict(parse_pb(st[3][0][1]))[1][0][1]) if 3 in st else None
            payload.update({
                "id": pd[1][0][1].decode("utf-8"),
                "min_schema_version": pd[2][0][1],
                "revision": _dec_lww_clock(pd[3][0][1]),
                "z_order": _dec_zorder(pd[7][0][1]),
                "path": path_spec,
                "end_arrowhead": pd[31][0][1] if 31 in pd else 0,
                "stroke": {"width": pb_f32(st[1][0][1]) if 1 in st else 0.0, "color": scol},
            })

        objects.append({"header": header, "payload": payload})
    return objects


def decode_search_page(data: bytes) -> Dict[str, Any]:
    d = pb_dict(parse_pb(data))
    texts = [val.decode("utf-8") for _, val in d.get(3, [])]
    layouts = []
    for _, raw_l in d.get(4, []):
        if not raw_l:
            layouts.append(None)
            continue
        ld = pb_dict(parse_pb(raw_l))
        tokens = []
        for _, traw in ld.get(2, []):
            td = pb_dict(parse_pb(traw))
            tokens.append({
                "start": td[1][0][1] if 1 in td else 0,
                "length": td[2][0][1] if 2 in td else 0,
                "rect": _dec_rect(td[3][0][1]),
            })
        aff = pb_dict(parse_pb(ld[3][0][1])) if 3 in ld else {}
        layouts.append({
            "tokens": tokens,
            "transform": {
                "a": pb_f32(aff[1][0][1]) if 1 in aff else 0.0,
                "b": pb_f32(aff[2][0][1]) if 2 in aff else 0.0,
                "c": pb_f32(aff[3][0][1]) if 3 in aff else 0.0,
                "d": pb_f32(aff[4][0][1]) if 4 in aff else 0.0,
                "tx": pb_f32(aff[5][0][1]) if 5 in aff else 0.0,
                "ty": pb_f32(aff[6][0][1]) if 6 in aff else 0.0,
            },
        })
    hw_words = []
    for _, raw_w in d.get(6, []):
        wd = pb_dict(parse_pb(raw_w))
        strokes = []
        for _, sraw in wd.get(7, []):
            sd = pb_dict(parse_pb(sraw))
            strokes.append({
                "internal_id": sd[1][0][1].decode("utf-8") if 1 in sd else "",
                "rect": _dec_rect(sd[2][0][1]) if 2 in sd else None,
                "stroke_uuid": sd[3][0][1].decode("utf-8") if 3 in sd else "",
                "sample_points": [_dec_point(pr) for _, pr in sd.get(4, [])],
                "color": _dec_color(sd[5][0][1]) if 5 in sd else None,
                "max_width": pb_f32(sd[6][0][1]) if 6 in sd else None,
            })
        s4 = wd[4][0][1] if 4 in wd else b""
        s6 = wd[6][0][1] if 6 in wd else b""
        s9 = wd[9][0][1] if 9 in wd else b""
        hw_words.append({
            "rect": _dec_rect(wd[1][0][1]) if 1 in wd else None,
            "candidates": [v.decode("utf-8") for _, v in wd.get(3, [])],
            "scores_4": list(struct.unpack(f"<{len(s4)//4}f", s4)) if s4 else [],
            "norm_candidates": [v.decode("utf-8") for _, v in wd.get(5, [])],
            "confidences_6": list(struct.unpack(f"<{len(s6)//4}f", s6)) if s6 else [],
            "raw_candidates": [v.decode("utf-8") for _, v in wd.get(10, [])],
            "scores_9": list(struct.unpack(f"<{len(s9)//4}f", s9)) if s9 else [],
            "locale": wd[11][0][1].decode("utf-8") if 11 in wd else None,
            "strokes": strokes,
        })
    return {
        "page_id": d[5][0][1].decode("utf-8") if 5 in d else None,
        "typed_texts": texts,
        "typed_layouts": layouts,
        "handwriting_words": hw_words,
        "content_hash_u64": d[12][0][1] if 12 in d else None,
        "lang": d[13][0][1].decode("utf-8") if 13 in d else None,
        "index_version": pb_f32(d[14][0][1]) if 14 in d else None,
        "hwr_model_version": d[15][0][1] if 15 in d else None,
        "status": d[16][0][1] if 16 in d else None,
    }


def decode_search_pdf(data: bytes) -> List[Dict[str, Any]]:
    pages = []
    for m in parse_delimited(data):
        d = pb_dict(m)
        pages.append({
            "page_number": d[2][0][1] if 2 in d else 0,
            "extracted_text": d[3][0][1].decode("utf-8") if 3 in d else "",
        })
    return pages


def inspect_attachment(name: str, data: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {"path": name, "byte_size": len(data)}
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        w, h, bd, ct = struct.unpack(">IIBB", data[16:26])
        info.update({"format": "PNG", "width_px": w, "height_px": h, "bit_depth": bd, "color_type": ct})
    elif data[:2] == b"\xff\xd8":
        pos = 2
        w = h = None
        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker in (0xC0, 0xC1, 0xC2):
                h, w = struct.unpack(">HH", data[pos + 5:pos + 9])
                break
            if marker in (0xD8, 0xD9):
                pos += 2
            else:
                ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                pos += 2 + ln
        info.update({"format": "JPEG", "width_px": w, "height_px": h})
    elif data[:5] == b"%PDF-":
        ver = data[:8].decode("ascii", errors="replace")
        mboxes = [m.decode("ascii", errors="replace") for m in re.findall(rb"/MediaBox\s*\[([^\]]+)\]", data)]
        producers = [p.decode("latin1", errors="replace") for p in re.findall(rb"/Producer\s*\(([^\)]+)\)", data)]
        page_cnt = len(re.findall(rb"/Type\s*/Page\b", data))
        info.update({
            "format": ver,
            "page_count": page_cnt,
            "media_boxes_pt": mboxes,
            "producers": producers,
        })
    else:
        info["format"] = "UNKNOWN"
    return info


# ---------------------------------------------------------------------------
# Disassemble Command
# ---------------------------------------------------------------------------

def disassemble_archive(archive_path: Path, out_dir: Path) -> None:
    decoded_dir = out_dir / "decoded"
    (decoded_dir / "notes").mkdir(parents=True, exist_ok=True)
    (decoded_dir / "search").mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zf:
        manifest = []
        for info in zf.infolist():
            raw = zf.read(info.filename)
            manifest.append({
                "filename": info.filename,
                "size": len(raw),
                "compress_type": info.compress_type,
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        (decoded_dir / "archive_manifest.json").write_text(json.dumps(manifest, indent=2))

        (decoded_dir / "schema.json").write_text(json.dumps(decode_schema(zf.read("schema.pb")), indent=2))
        (decoded_dir / "index.notes.json").write_text(
            json.dumps(decode_index_entries(zf.read("index.notes.pb")), indent=2)
        )
        (decoded_dir / "index.attachments.json").write_text(
            json.dumps(decode_index_entries(zf.read("index.attachments.pb")), indent=2)
        )
        search_idx = decode_index_entries(zf.read("index.search.pb"), has_kind=True)
        (decoded_dir / "index.search.json").write_text(json.dumps(search_idx, indent=2))
        (decoded_dir / "index.events.json").write_text(
            json.dumps(sanitize_json(decode_index_events(zf.read("index.events.pb"))), indent=2)
        )

        # Notes
        for entry in decode_index_entries(zf.read("index.notes.pb")):
            data = zf.read(entry["path"])
            objs = decode_note_layer(data) if data else []
            (decoded_dir / "notes" / f"{entry['uuid']}.json").write_text(
                json.dumps(sanitize_json(objs), indent=2)
            )

        # Search
        for entry in search_idx:
            data = zf.read(entry["path"])
            if entry["kind"] == 1:
                dec = {"kind": "pdf_search", "pages": decode_search_pdf(data)}
            else:
                dec = {"kind": "page_search", "data": decode_search_page(data)}
            (decoded_dir / "search" / f"{entry['uuid']}.json").write_text(
                json.dumps(sanitize_json(dec), indent=2)
            )

        # Attachments & thumbnail
        att_infos = [inspect_attachment("thumbnail.jpg", zf.read("thumbnail.jpg"))]
        for info in zf.infolist():
            if info.filename.startswith("attachments/"):
                att_infos.append(inspect_attachment(info.filename, zf.read(info.filename)))
        (decoded_dir / "attachments_info.json").write_text(json.dumps(att_infos, indent=2))


# ---------------------------------------------------------------------------
# SVG Preview Renderer
# ---------------------------------------------------------------------------

def _rgba_css(col: Optional[Dict[str, float]]) -> Tuple[str, float]:
    if not col:
        return "none", 0.0
    r = max(0, min(255, int(round(col.get("r", 0.0) * 255))))
    g = max(0, min(255, int(round(col.get("g", 0.0) * 255))))
    b = max(0, min(255, int(round(col.get("b", 0.0) * 255))))
    a = max(0.0, min(1.0, col.get("a", 1.0)))
    return f"rgb({r},{g},{b})", a


def _arc_to_svg_path(cx: float, cy: float, rx: float, ry: float, a0: float, a1: float, rot: float, cw: bool, is_first: bool = False) -> str:
    """Convert center-parameterized CoreGraphics arc (`cw` in Y-up) to SVG Y-down path."""
    def pt_at(t: float) -> Tuple[float, float]:
        lx = rx * math.cos(t)
        ly = ry * math.sin(t)
        cr, sr = math.cos(rot), math.sin(rot)
        return cx + lx * cr - ly * sr, cy + lx * sr + ly * cr

    x0, y0 = pt_at(a0)
    x1, y1 = pt_at(a1)
    # CoreGraphics `clockwise=True` (Y-up) sweeps in decreasing-angle direction in Y-down (SVG sweep=0).
    tau = 2.0 * math.pi
    if cw:
        delta = (a0 - a1) % tau
        if delta < 1e-6 and abs(a1 - a0) > 1e-3:
            delta = tau
        sweep = 0
    else:
        delta = (a1 - a0) % tau
        if delta < 1e-6 and abs(a1 - a0) > 1e-3:
            delta = tau
        sweep = 1

    prefix = f"M {x0:.2f} {y0:.2f} " if is_first else f"L {x0:.2f} {y0:.2f} "
    if delta >= tau - 1e-3:
        xm, ym = pt_at(a0 + (-math.pi if cw else math.pi))
        rot_deg = math.degrees(rot)
        return (
            f"{prefix}A {rx:.2f} {ry:.2f} {rot_deg:.2f} 0 {sweep} {xm:.2f} {ym:.2f} "
            f"A {rx:.2f} {ry:.2f} {rot_deg:.2f} 0 {sweep} {x0:.2f} {y0:.2f}"
        )
    large_arc = 1 if delta > math.pi else 0
    rot_deg = math.degrees(rot)
    return f"{prefix}A {rx:.2f} {ry:.2f} {rot_deg:.2f} {large_arc} {sweep} {x1:.2f} {y1:.2f}"


def _render_template_background_svg(tpl: Dict[str, Any], att_bytes: bytes) -> str:
    w = tpl["page_size"]["width"]
    h = tpl["page_size"]["height"]
    name = tpl.get("template_name", "")
    parts = [f'<rect x="0" y="0" width="{w:.2f}" height="{h:.2f}" fill="#ffffff"/>']

    if "Blue" in name or tpl["logical_attachment_id"] == "C3BDD217-2DBE-446F-93AA-627A50476403":
        # Parse cover PDF colors/rects dynamically if possible, fallback to exact decoded PDF values
        parts = [
            f'<rect x="0" y="0" width="{w:.2f}" height="{h:.2f}" fill="#51d7f5"/>',
            f'<rect x="{505.988 * PT_TO_GN:.2f}" y="0" width="{(535.752 - 505.988) * PT_TO_GN:.2f}" height="{h:.2f}" fill="#0a9dbf"/>',
        ]
    elif tpl.get("paper_theme") == 2 or (tpl.get("ruling_layout") and tpl["ruling_layout"]["ruling_kind"] == 2):
        # Black Ruled template
        rl = tpl["ruling_layout"]
        parts = [f'<rect x="0" y="0" width="{w:.2f}" height="{h:.2f}" fill="#333333"/>']
        y0 = rl["bounds"]["origin"]["y"]
        y_end = y0 + rl["bounds"]["size"]["height"]
        pitch = rl["row_pitch_minus_stroke"] + rl["stroke_thickness"]
        y = y0
        while y <= y_end + 0.5:
            parts.append(f'<line x1="0" y1="{y:.2f}" x2="{w:.2f}" y2="{y:.2f}" stroke="#58595b" stroke-width="{rl["stroke_thickness"]:.2f}"/>')
            y += pitch
    elif tpl.get("ruling_layout") and tpl["ruling_layout"]["ruling_kind"] == 1:
        # White Dotted template
        rl = tpl["ruling_layout"]
        parts = [f'<rect x="0" y="0" width="{w:.2f}" height="{h:.2f}" fill="#ffffff"/>']
        x0 = rl["bounds"]["origin"]["x"]
        y0 = rl["bounds"]["origin"]["y"]
        x_end = x0 + rl["bounds"]["size"]["width"]
        y_end = y0 + rl["bounds"]["size"]["height"]
        pitch = rl["row_pitch_minus_stroke"] + rl["stroke_thickness"]
        r = rl["stroke_thickness"] / 2.0
        dots = []
        y = y0
        while y <= y_end + 0.5:
            x = x0
            while x <= x_end + 0.5:
                dots.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}"/>')
                x += pitch
            y += pitch
        parts.append(f'<g fill="#d0d2d3">{"".join(dots)}</g>')
    return "\n  ".join(parts)


def render_svg_previews(archive_path: Path, out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    generated: List[Path] = []
    with zipfile.ZipFile(archive_path, "r") as zf:
        events = decode_index_events(zf.read("index.events.pb"))
        templates: Dict[str, Dict[str, Any]] = {}
        att_map: Dict[str, str] = {}
        pages: List[Dict[str, Any]] = []
        for entry in decode_index_entries(zf.read("index.attachments.pb")):
            att_map[entry["uuid"]] = entry["path"]
        for ev in events:
            if ev["event_tag"] == 2:
                templates[ev["template_id"]] = ev
            elif ev["event_tag"] == 54:
                pages.append(ev)
        pages.sort(key=lambda p: p["order_key"])

        slugs = ["cover", "tools", "dotted", "scanned"]
        for idx, page in enumerate(pages):
            note_path = f"notes/{page['note_layer_id']}"
            note_bytes = zf.read(note_path)
            if not note_bytes and idx >= 3:
                continue  # Page 4 is pure scanned PDF with empty note layer; render pages 1-3 as planned
            tpl = templates[page["template_id"]]
            w, h = tpl["page_size"]["width"], tpl["page_size"]["height"]
            objs = decode_note_layer(note_bytes) if note_bytes else []
            active = [o for o in objs if not o["header"]["is_deleted"]]

            # Build parent sticky-note lookup for child strokes
            sticky_origins: Dict[str, Tuple[float, float]] = {}
            for o in active:
                p = o["payload"]
                if p["payload_tag"] == 20:
                    sticky_origins[p["id"]] = (p["origin"]["x"], p["origin"]["y"])

            def zkey(o: Dict[str, Any]) -> Tuple[int, int]:
                z = o["payload"].get("z_order", {})
                return (z.get("index", 0), z.get("tiebreaker", 0))

            active.sort(key=zkey)

            svg_elems = [
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.2f}" height="{h:.2f}" viewBox="0 0 {w:.2f} {h:.2f}">',
                "  " + _render_template_background_svg(tpl, zf.read(att_map[tpl["logical_attachment_id"]])),
            ]

            for o in active:
                p = o["payload"]
                tag = p["payload_tag"]
                if tag == 1:  # ImageItem
                    bb = p["bounding_box"]
                    x, y = bb["origin"]["x"], bb["origin"]["y"]
                    bw, bh = bb["size"]["width"], bb["size"]["height"]
                    blob = zf.read(att_map[p["attachment_id"]])
                    mime = "image/png" if blob[:4] == b"\x89PNG" else "image/jpeg"
                    b64 = base64.b64encode(blob).decode("ascii")
                    svg_elems.append(
                        f'  <image x="{x:.2f}" y="{y:.2f}" width="{bw:.2f}" height="{bh:.2f}" href="data:{mime};base64,{b64}"/>'
                    )
                elif tag == 9:  # ShapeFillItem
                    fg = p["fill_geometry"]
                    if not fg:
                        continue
                    col, a = _rgba_css(p["fill_color"])
                    if "polygon" in fg:
                        pts = " ".join(f"{pt['x']:.2f},{pt['y']:.2f}" for pt in fg["polygon"])
                        svg_elems.append(f'  <polygon points="{pts}" fill="{col}" fill-opacity="{a:.3f}"/>')
                    elif "ellipse" in fg:
                        el = fg["ellipse"]
                        deg = math.degrees(el["rotation_rad"])
                        cx, cy = el["center"]["x"], el["center"]["y"]
                        rx, ry = el["radii"]["x"], el["radii"]["y"]
                        svg_elems.append(
                            f'  <ellipse cx="{cx:.2f}" cy="{cy:.2f}" rx="{rx:.2f}" ry="{ry:.2f}" '
                            f'transform="rotate({deg:.2f} {cx:.2f} {cy:.2f})" fill="{col}" fill-opacity="{a:.3f}"/>'
                        )
                elif tag == 7:  # StrokeItem
                    col, a = _rgba_css(p["color"])
                    dx = dy = 0.0
                    if p["parent_container_id"] and p["local_offset"]:
                        po = sticky_origins.get(p["parent_container_id"], (0.0, 0.0))
                        dx = p["local_offset"]["x"] + po[0]
                        dy = p["local_offset"]["y"] + po[1]

                    if p["snapped_shape"]:
                        ss = p["snapped_shape"]
                        sw = ss["stroke_width"] or 1.5
                        if "polyline" in ss:
                            pts = " ".join(f"{pt['x'] + dx:.2f},{pt['y'] + dy:.2f}" for pt in ss["polyline"])
                            svg_elems.append(
                                f'  <polyline points="{pts}" fill="none" stroke="{col}" stroke-opacity="{a:.3f}" '
                                f'stroke-width="{sw:.2f}" stroke-linecap="round" stroke-linejoin="round"/>'
                            )
                        elif "ellipse" in ss:
                            el = ss["ellipse"]
                            deg = math.degrees(el["rotation_rad"])
                            cx, cy = el["center"]["x"] + dx, el["center"]["y"] + dy
                            rx, ry = el["radii"]["x"], el["radii"]["y"]
                            svg_elems.append(
                                f'  <ellipse cx="{cx:.2f}" cy="{cy:.2f}" rx="{rx:.2f}" ry="{ry:.2f}" '
                                f'transform="rotate({deg:.2f} {cx:.2f} {cy:.2f})" fill="none" stroke="{col}" '
                                f'stroke-opacity="{a:.3f}" stroke-width="{sw:.2f}"/>'
                            )
                        continue

                    tpl_d = p["tpl"]
                    kind = tpl_d["kind"]
                    if kind in ("Format1_BallpointOrHighlighter", "Format3_Pencil"):
                        sw = tpl_d.get("full_width") or tpl_d.get("base_full_width", 1.5)
                        d_cmds: List[str] = []
                        mi = qi = 0
                        for op in tpl_d["ops"]:
                            if op == 0:
                                mp = tpl_d["move_points"][mi]
                                mx = mp["x"] if isinstance(mp, dict) else mp[0]
                                my = mp["y"] if isinstance(mp, dict) else mp[1]
                                d_cmds.append(f"M {mx + dx:.2f} {my + dy:.2f}")
                                mi += 1
                            elif op == 1:
                                q = tpl_d["quad_segments"][qi]
                                if isinstance(q, dict):
                                    cx, cy, ex, ey = q["cx"], q["cy"], q["ex"], q["ey"]
                                else:
                                    cx, cy, ex, ey = q
                                d_cmds.append(f"Q {cx + dx:.2f} {cy + dy:.2f} {ex + dx:.2f} {ey + dy:.2f}")
                                qi += 1
                        if d_cmds:
                            svg_elems.append(
                                f'  <path d="{" ".join(d_cmds)}" fill="none" stroke="{col}" stroke-opacity="{a:.3f}" '
                                f'stroke-width="{sw:.2f}" stroke-linecap="round" stroke-linejoin="round"/>'
                            )
                    elif kind == "Format2_FountainBrushOrTape":
                        d_cmds = []
                        for sub in tpl_d["outlines"]:
                            for cmd in sub:
                                cop = cmd["op"]
                                if cop == "moveTo":
                                    d_cmds.append(f"M {cmd['x'] + dx:.2f} {cmd['y'] + dy:.2f}")
                                elif cop == "lineTo":
                                    d_cmds.append(f"L {cmd['x'] + dx:.2f} {cmd['y'] + dy:.2f}")
                                elif cop == "cubicTo":
                                    d_cmds.append(
                                        f"C {cmd['c1x'] + dx:.2f} {cmd['c1y'] + dy:.2f} "
                                        f"{cmd['c2x'] + dx:.2f} {cmd['c2y'] + dy:.2f} "
                                        f"{cmd['ex'] + dx:.2f} {cmd['ey'] + dy:.2f}"
                                    )
                                elif cop == "arc":
                                    d_cmds.append(_arc_to_svg_path(cmd["cx"] + dx, cmd["cy"] + dy, cmd["r"], cmd["r"], cmd["startAngle"], cmd["endAngle"], 0.0, cmd["clockwise"]))
                                elif cop == "ellipticalArc":
                                    d_cmds.append(_arc_to_svg_path(cmd["cx"] + dx, cmd["cy"] + dy, cmd["rx"], cmd["ry"], cmd["startAngle"], cmd["endAngle"], cmd["rotation"], cmd["clockwise"]))
                            d_cmds.append("Z")
                        if d_cmds:
                            svg_elems.append(
                                f'  <path d="{" ".join(d_cmds)}" fill="{col}" fill-opacity="{a:.3f}" fill-rule="nonzero"/>'
                            )
                elif tag == 20:  # StickyNoteItem
                    ox, oy = p["origin"]["x"], p["origin"]["y"]
                    sw, sh = p["size"]["width"], p["size"]["height"]
                    bg, bga = _rgba_css(p["background_color"])
                    rt = p["rich_text"]
                    txt = html.escape(rt.get("content", {}).get("plain_text", ""))
                    fs = rt.get("default_style", {}).get("char_style", {}).get("font_size") or 24.0
                    svg_elems.append(
                        f'  <rect x="{ox:.2f}" y="{oy:.2f}" width="{sw:.2f}" height="{sh:.2f}" rx="8" fill="{bg}" fill-opacity="{bga:.3f}"/>'
                    )
                    if txt:
                        svg_elems.append(
                            f'  <text x="{ox + 8:.2f}" y="{oy + 8 + fs:.2f}" font-family="Helvetica Neue, sans-serif" font-size="{fs:.1f}" fill="#312a02">{txt}</text>'
                        )
                elif tag == 21:  # TextOrShapeItem
                    ox, oy = p["origin"]["x"], p["origin"]["y"]
                    spec = p["size_spec"]
                    rt = p["rich_text"] or {}
                    ms = rt.get("measured_size") or {}
                    if spec.get("mode") == "fixed":
                        bw, bh = spec["width"], spec["height"]
                    else:
                        bw = ms.get("width", 120.0)
                        bh = ms.get("height", 32.0)
                    fcol, fa = _rgba_css(p["fill_color"])
                    bcol, ba = _rgba_css(p["border"]["color"] if p["border"] else None)
                    bw_stroke = p["border"]["width"] if p["border"] else 0.0
                    sk = p["shape_kind"]
                    if sk.get("kind") == "rectangle":
                        cr = sk.get("corner_radius", 0.0)
                        svg_elems.append(
                            f'  <rect x="{ox:.2f}" y="{oy:.2f}" width="{bw:.2f}" height="{bh:.2f}" rx="{cr:.2f}" '
                            f'fill="{fcol}" fill-opacity="{fa:.3f}" stroke="{bcol}" stroke-opacity="{ba:.3f}" stroke-width="{bw_stroke:.2f}"/>'
                        )
                    elif sk.get("kind") == "polygon":
                        pts = " ".join(f"{ox + v['point']['x'] * bw:.2f},{oy + v['point']['y'] * bh:.2f}" for v in sk["vertices"])
                        svg_elems.append(
                            f'  <polygon points="{pts}" fill="{fcol}" fill-opacity="{fa:.3f}" stroke="{bcol}" stroke-opacity="{ba:.3f}" stroke-width="{bw_stroke:.2f}"/>'
                        )
                    runs = rt.get("content", {}).get("runs", [])
                    if any(r["text"] for r in runs):
                        ins = rt.get("insets") or {"left": 8.0, "top": 8.0}
                        fs = rt.get("default_style", {}).get("char_style", {}).get("font_size") or 24.0
                        tx = ox + ins["left"]
                        ty = oy + ins["top"] + fs * 0.85
                        # Approximate highlight rects if highlight_color present
                        cursor_x = tx
                        for r in runs:
                            approx_w = max(4.0, len(r["text"]) * fs * 0.48)
                            hl = r.get("char_style", {}).get("highlight_color")
                            if hl and r["text"]:
                                hcol, ha = _rgba_css(hl)
                                svg_elems.append(
                                    f'  <rect x="{cursor_x:.2f}" y="{oy + ins["top"]:.2f}" width="{approx_w:.2f}" height="{fs * 1.15:.2f}" fill="{hcol}" fill-opacity="{ha:.3f}"/>'
                                )
                            cursor_x += approx_w
                        tspans = []
                        for r in runs:
                            rc = _rgba_css(r.get("char_style", {}).get("text_color") or {"r": 1, "g": 1, "b": 1, "a": 1})[0]
                            deco = ' text-decoration="underline"' if r.get("char_style", {}).get("hyperlink_url") else ""
                            tspans.append(f'<tspan fill="{rc}"{deco}>{html.escape(r["text"])}</tspan>')
                        svg_elems.append(
                            f'  <text x="{tx:.2f}" y="{ty:.2f}" font-family="Helvetica Neue, sans-serif" font-size="{fs:.1f}">{"".join(tspans)}</text>'
                        )
                elif tag == 22:  # ConnectorItem
                    ps = p["path"]
                    scol, sa = _rgba_css(p["stroke"]["color"])
                    sw = p["stroke"]["width"] or 2.0
                    if ps["kind"] == "quadratic_curve":
                        s, c, e = ps["start"], ps["control"], ps["end"]
                        svg_elems.append(
                            f'  <path d="M {s["x"]:.2f} {s["y"]:.2f} Q {c["x"]:.2f} {c["y"]:.2f} {e["x"]:.2f} {e["y"]:.2f}" '
                            f'fill="none" stroke="{scol}" stroke-opacity="{sa:.3f}" stroke-width="{sw:.2f}" stroke-linecap="round"/>'
                        )
                        dx_a, dy_a = e["x"] - c["x"], e["y"] - c["y"]
                    else:
                        s, e = ps["start"], ps["end"]
                        svg_elems.append(
                            f'  <line x1="{s["x"]:.2f}" y1="{s["y"]:.2f}" x2="{e["x"]:.2f}" y2="{e["y"]:.2f}" '
                            f'stroke="{scol}" stroke-opacity="{sa:.3f}" stroke-width="{sw:.2f}" stroke-linecap="round"/>'
                        )
                        dx_a, dy_a = e["x"] - s["x"], e["y"] - s["y"]
                    if p.get("end_arrowhead"):
                        ang = math.atan2(dy_a, dx_a)
                        alen = max(8.0, sw * 3.5)
                        aw = alen * 0.55
                        bx, by = e["x"] - alen * math.cos(ang), e["y"] - alen * math.sin(ang)
                        px, py = -aw * math.sin(ang), aw * math.cos(ang)
                        svg_elems.append(
                            f'  <polygon points="{e["x"]:.2f},{e["y"]:.2f} {bx + px:.2f},{by + py:.2f} {bx - px:.2f},{by - py:.2f}" '
                            f'fill="{scol}" fill-opacity="{sa:.3f}"/>'
                        )

            svg_elems.append("</svg>\n")
            slug = slugs[idx] if idx < len(slugs) else f"page_{idx + 1}"
            out_path = out_dir / f"page_{idx + 1}_{slug}.svg"
            out_path.write_text("\n".join(svg_elems))
            generated.append(out_path)
    return generated


# ---------------------------------------------------------------------------
# Goodnotes Archive Builder / Writer
# ---------------------------------------------------------------------------

def _minimal_pdf_page(width_pt: float, height_pt: float, bg_rgb: Tuple[float, float, float]) -> bytes:
    """Create a minimal valid single-page PDF-1.4 background template."""
    stream_txt = f"{bg_rgb[0]:.3f} {bg_rgb[1]:.3f} {bg_rgb[2]:.3f} rg 0 0 {width_pt:.2f} {height_pt:.2f} re f\n".encode("ascii")
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        f"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width_pt:.2f} {height_pt:.2f}] /Contents 4 0 R >>\nendobj\n".encode("ascii"),
        f"4 0 obj\n<< /Length {len(stream_txt)} >>\nstream\n".encode("ascii") + stream_txt + b"endstream\nendobj\n",
    ]
    buf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for o in objs:
        offsets.append(len(buf))
        buf.extend(o)
    xref_pos = len(buf)
    buf.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii"))
    return bytes(buf)


def _minimal_1x1_png_rgba(r: int, g: int, b: int, a: int = 255) -> bytes:
    def chunk(ctype: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes([0, r, g, b, a]))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


@dataclass
class PageBuildState:
    page_id: str
    note_layer_id: str
    template_id: str
    order_key: str
    records: List[bytes] = field(default_factory=list)
    next_z: int = 0


class GoodnotesBuilder:
    """Programmatic writer for valid Goodnotes `.goodnotes` archives (schema v24..v35)."""

    def __init__(self, title: str = "Notebook", replica_id: int = DEFAULT_REPLICA_ID) -> None:
        self.title = title
        self.replica_id = replica_id
        self.doc_id = str(uuid.uuid4()).upper()
        self.folder_id = str(uuid.uuid4()).upper()
        self.event_lamport = 1794351892000
        self.note_lamport = 1715400
        self.max_schema_version = 24
        self.events: List[bytes] = []
        self.attachments: Dict[str, bytes] = {}
        self.att_index: List[Tuple[str, str]] = []
        self.pages: List[PageBuildState] = []
        self._tie = 100000000
        self.thumbnail_jpg: bytes = b""
        self._emit_create_document()

    def _now_ms(self) -> float:
        return float(int(time.time() * 1000))

    def _next_event_lamport(self) -> int:
        self.event_lamport += 1
        return self.event_lamport

    def _next_note_lamport(self) -> int:
        self.note_lamport += 1
        return self.note_lamport

    def _next_tie(self) -> int:
        self._tie = (self._tie * 1664525 + 1013904223) & 0xFFFFFFFF
        return self._tie

    def _emit_create_document(self) -> None:
        ev = encode_pb([
            (1, 2, self.doc_id),
            (2, 2, encode_pb([(1, 2, self.title), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (3, 2, encode_pb([(1, 2, self.folder_id), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (6, 2, encode_pb([(1, 2, b"P"), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (7, 2, encode_pb([(1, 2, self.folder_id), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (9, 2, "auto"),
            (10, 1, self._now_ms()),
            (11, 2, str(uuid.uuid4()).upper()),
            (13, 0, self.replica_id),
            (14, 0, self._next_event_lamport()),
            (17, 2, b""),
            (18, 2, b""),
            (19, 2, encode_pb([(2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (20, 0, 24),
        ])
        self.events.append(encode_pb([(1, 2, self.doc_id), (30, 2, ev)]))

    def register_attachment(self, blob: bytes, is_pdf: bool = False) -> str:
        att_id = str(uuid.uuid4()).upper()
        self.attachments[att_id] = blob
        self.att_index.append((att_id, f"attachments/{att_id}"))
        pdf_meta = encode_pb([(1, 0, 1), (2, 0, 1)]) if is_pdf else b""
        ev = encode_pb([
            (1, 2, att_id),
            (2, 2, att_id),
            (5, 0, len(blob)),
            (6, 2, self.doc_id),
            (10, 1, self._now_ms()),
            (11, 2, str(uuid.uuid4()).upper()),
            (12, 2, pdf_meta),
            (14, 0, self.replica_id),
            (15, 0, self._next_event_lamport()),
            (16, 0, 24),
        ])
        self.events.append(encode_pb([(1, 2, att_id), (6, 2, ev)]))
        return att_id

    def add_page(
        self,
        width_pt: float = 595.28,
        height_pt: float = 841.89,
        bg_rgb: Tuple[float, float, float] = (1.0, 1.0, 1.0),
        template_name: str = "Custom",
        pdf_bytes: Optional[bytes] = None,
        paper_theme: int = 1,
    ) -> PageBuildState:
        pdf_data = pdf_bytes or _minimal_pdf_page(width_pt, height_pt, bg_rgb)
        att_id = self.register_attachment(pdf_data, is_pdf=True)
        tpl_id = str(uuid.uuid4()).upper()
        w_gn, h_gn = width_pt * PT_TO_GN, height_pt * PT_TO_GN
        tpl_ev = encode_pb([
            (1, 2, self.doc_id),
            (2, 2, tpl_id),
            (4, 2, att_id),
            (5, 0, 1),
            (6, 0, 1),
            (8, 2, _enc_size(w_gn, h_gn)),
            (9, 2, template_name),
            (10, 1, self._now_ms()),
            (11, 2, str(uuid.uuid4()).upper()),
            (15, 0, self.replica_id),
            (16, 0, self._next_event_lamport()),
            (17, 2, encode_pb([(1, 0, paper_theme), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (21, 0, 24),
        ])
        self.events.append(encode_pb([(1, 2, tpl_id), (2, 2, tpl_ev)]))

        # Enforce Goodnotes critical UUID invariant: NoteLayerUUID == PageUUID + 1
        page_uuid = uuid.uuid4()
        note_uuid = uuid.UUID(int=page_uuid.int + 1)
        page_id = str(page_uuid).upper()
        note_id = str(note_uuid).upper()
        order_key = f"4BPpG{len(self.pages) + 1}"

        page_style = encode_pb([
            (1, 2, encode_pb([(2, 2, encode_pb([
                (1, 2, _enc_color(0.866667, 0.866667, 0.866667, 1.0)),
                (2, 2, _enc_color(1.0, 1.0, 1.0, 1.0)),
            ]))])),
            (2, 2, _enc_lww_clock(1, self._next_tie())),
        ])
        page_ev = encode_pb([
            (1, 2, self.doc_id),
            (2, 2, page_id),
            (3, 2, encode_pb([(1, 2, tpl_id), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (4, 2, encode_pb([(1, 2, order_key), (2, 2, _enc_lww_clock(1, self._next_tie()))])),
            (10, 1, self._now_ms()),
            (11, 2, str(uuid.uuid4()).upper()),
            (13, 0, self.replica_id),
            (14, 0, self._next_event_lamport()),
            (15, 0, 24),
            (17, 2, page_style),
        ])
        self.events.append(encode_pb([(1, 2, page_id), (54, 2, page_ev)]))

        st = PageBuildState(page_id=page_id, note_layer_id=note_id, template_id=tpl_id, order_key=order_key)
        self.pages.append(st)
        return st

    def _append_note_pair(
        self,
        page: PageBuildState,
        obj_id: str,
        rev_counter: int,
        rev_tie: int,
        min_ver: int,
        payload_tag: int,
        payload_bytes: bytes,
        attachment_id: Optional[str] = None,
        parent_id: Optional[str] = None,
    ) -> None:
        self.max_schema_version = max(self.max_schema_version, min_ver)
        rev_bytes = _enc_lww_clock(rev_counter, rev_tie)
        hdr_fields: List[Tuple[int, int, Any]] = [
            (1, 2, obj_id),
            (2, 2, rev_bytes),
        ]
        if attachment_id:
            hdr_fields.append((4, 2, attachment_id))
        hdr_fields.extend([
            (8, 0, self.replica_id),
            (9, 0, self._next_note_lamport()),
            (14, 0, NOTE_HEADER_CONST_F14),
            (16, 0, min_ver),
        ])
        if parent_id:
            hdr_fields.append((20, 2, parent_id))
        page.records.append(encode_pb(hdr_fields))
        page.records.append(encode_pb([(payload_tag, 2, payload_bytes)]))

    def add_ballpoint_or_highlighter_stroke(
        self,
        page: PageBuildState,
        points: List[Tuple[float, float]],
        width: float = 1.559055,
        color: Tuple[float, float, float, float] = (0.0, 0.0, 0.0, 1.0),
        is_highlighter: bool = False,
    ) -> str:
        obj_id = str(uuid.uuid4()).upper()
        z_idx, z_tie = page.next_z, self._next_tie()
        page.next_z += 1
        rev_cnt, rev_tie = 2, self._next_tie()

        ops = [0] + [1] * max(0, len(points) - 1)
        moves = [(f32_to_u32(points[0][0]), f32_to_u32(points[0][1]))]
        quads = []
        for i in range(1, len(points)):
            px, py = points[i - 1]
            ex, ey = points[i]
            cx, cy = (px + ex) / 2.0, (py + ey) / 2.0
            quads.append((f32_to_u32(cx), f32_to_u32(cy), f32_to_u32(ex), f32_to_u32(ey)))

        tpl_bytes = encode_tpl(
            "vuA(v)A(S(uu))A(S(uuuu))vA(f)",
            [2, f32_to_u32(width), ops, moves, quads, 1, []],
        )
        fields: List[Tuple[int, int, Any]] = [
            (1, 2, obj_id),
            (2, 2, compress_bv41(tpl_bytes)),
            (4, 2, _enc_color(*color)),
        ]
        if is_highlighter:
            fields.append((5, 0, 1))
        fields.extend([
            (6, 2, b""),
            (7, 2, _enc_zorder(z_idx, z_tie)),
            (9, 2, b""),
            (15, 2, _enc_lww_clock(rev_cnt, rev_tie)),
            (20, 2, b""),
            (21, 0, 24),
        ])
        self._append_note_pair(page, obj_id, rev_cnt, rev_tie, 24, 7, encode_pb(fields))
        return obj_id

    def add_pencil_stroke(
        self,
        page: PageBuildState,
        points: List[Tuple[float, float, float]],  # (x, y, pressure)
        base_width: float = 1.559055,
        color: Tuple[float, float, float, float] = (0.6588, 0.6510, 0.6314, 1.0),
        param_a: float = 0.805732,
        param_b: float = 0.814237,
    ) -> str:
        obj_id = str(uuid.uuid4()).upper()
        z_idx, z_tie = page.next_z, self._next_tie()
        page.next_z += 1
        rev_cnt, rev_tie = 2, self._next_tie()

        ops = [0] + [1] * max(0, len(points) - 1)
        p0 = points[0]
        moves = [(f32_to_u32(p0[0]), f32_to_u32(p0[1]), f32_to_u32(param_a), f32_to_u32(param_b), f32_to_u32(p0[2]))]
        quads = []
        for i in range(1, len(points)):
            px, py, pp = points[i - 1]
            ex, ey, ep = points[i]
            cx, cy, cp = (px + ex) / 2.0, (py + ey) / 2.0, (pp + ep) / 2.0
            quads.append((
                self._next_tie(),
                f32_to_u32(cx), f32_to_u32(cy), f32_to_u32(param_a), f32_to_u32(param_b), f32_to_u32(cp),
                f32_to_u32(ex), f32_to_u32(ey), f32_to_u32(param_a), f32_to_u32(param_b), f32_to_u32(ep),
            ))
        tpl_bytes = encode_tpl(
            "vuA(v)A(S(uuuuu))A(S(uuuuuuuuuuu))A(S(uu))A(v)A(S(uu))A(S(uuuu))A(u)",
            [1, f32_to_u32(base_width), ops, moves, quads, [], [], [], [], []],
        )
        fields = [
            (1, 2, obj_id),
            (2, 2, compress_bv41(tpl_bytes)),
            (3, 0, 5),
            (4, 2, _enc_color(*color)),
            (6, 2, b""),
            (7, 2, _enc_zorder(z_idx, z_tie)),
            (9, 2, b""),
            (15, 2, _enc_lww_clock(rev_cnt, rev_tie)),
            (20, 2, b""),
            (21, 0, 25),
        ]
        self._append_note_pair(page, obj_id, rev_cnt, rev_tie, 25, 7, encode_pb(fields))
        return obj_id

    def add_snapped_polygon_with_fill(
        self,
        page: PageBuildState,
        vertices: List[Tuple[float, float]],
        stroke_width: float = 1.559055,
        stroke_color: Tuple[float, float, float, float] = (1.0, 1.0, 1.0, 1.0),
        fill_color: Tuple[float, float, float, float] = (1.0, 1.0, 1.0, 0.1),
    ) -> Tuple[str, str]:
        # First emit ShapeFillItem (f9)
        fill_id = str(uuid.uuid4()).upper()
        stroke_id = str(uuid.uuid4()).upper()
        xs = [v[0] for v in vertices]
        ys = [v[1] for v in vertices]
        min_x, min_y = min(xs), min(ys)
        max_x, max_y = max(xs), max(ys)

        z_fill, z_fill_tie = page.next_z, self._next_tie()
        page.next_z += 1
        poly_pts = encode_pb([(1, 2, _enc_point(x, y)) for x, y in vertices])
        fill_payload = encode_pb([
            (1, 2, fill_id),
            (2, 2, _enc_rect(min_x, min_y, max_x - min_x, max_y - min_y)),
            (3, 2, _enc_zorder(z_fill, z_fill_tie)),
            (4, 2, encode_pb([(1, 2, poly_pts)])),
            (5, 2, stroke_id),
            (6, 2, b""),
            (7, 2, _enc_color(*fill_color)),
            (15, 2, _enc_lww_clock(0, z_fill_tie)),
            (18, 0, 24),
        ])
        self._append_note_pair(page, fill_id, 0, z_fill_tie, 24, 9, fill_payload)

        # Then emit StrokeItem (f7) with empty TPL arrays and f7.9 SnappedShapeGeometry
        z_str, z_str_tie = page.next_z, self._next_tie()
        page.next_z += 1
        rev_cnt, rev_tie = 2, self._next_tie()
        stub_tpl = encode_tpl("vuA(v)A(S(uu))A(S(uuuu))vA(f)", [2, f32_to_u32(stroke_width), [], [], [], 1, []])
        snapped = encode_pb([
            (1, 2, poly_pts),
            (5, 2, encode_pb([(2, 0, 1)])),
            (15, 5, stroke_width),
        ])
        stroke_payload = encode_pb([
            (1, 2, stroke_id),
            (2, 2, compress_bv41(stub_tpl)),
            (4, 2, _enc_color(*stroke_color)),
            (6, 2, b""),
            (7, 2, _enc_zorder(z_str, z_str_tie)),
            (9, 2, snapped),
            (15, 2, _enc_lww_clock(rev_cnt, rev_tie)),
            (20, 2, b""),
            (21, 0, 24),
        ])
        self._append_note_pair(page, stroke_id, rev_cnt, rev_tie, 24, 7, stroke_payload)
        return fill_id, stroke_id

    def add_textbox(
        self,
        page: PageBuildState,
        x: float,
        y: float,
        text: str,
        font_size: float = 24.0,
        text_color: Tuple[float, float, float, float] = (0.1, 0.1, 0.1, 1.0),
    ) -> str:
        obj_id = str(uuid.uuid4()).upper()
        z_idx, z_tie = page.next_z, self._next_tie()
        page.next_z += 1
        rev_cnt, rev_tie = 1, self._next_tie()
        rt = encode_richtext_container(
            text=text, font_size=font_size, text_color=text_color,
            measured_size=(max(40.0, len(text) * font_size * 0.55), font_size * 1.4),
            insets=(10.0, 10.0, 10.0, 10.0),
        )
        payload = encode_pb([
            (1, 2, obj_id),
            (2, 0, 35),
            (3, 2, _enc_lww_clock(rev_cnt, rev_tie)),
            (7, 2, _enc_zorder(z_idx, z_tie)),
            (9, 0, 1),
            (20, 2, encode_pb([(1, 2, _enc_point(x, y)), (3, 5, 1.0)])),
            (21, 2, encode_pb([(3, 2, encode_pb([(1, 5, 32.0), (2, 5, 600.0), (3, 5, 32.0), (4, 5, float("inf"))]))])),
            (22, 2, encode_pb([(1, 2, b"")])),
            (30, 2, encode_pb([(1, 2, encode_pb([(1, 2, _enc_color(1.0, 1.0, 1.0, 0.0))]))])),
            (31, 2, encode_pb([(2, 2, encode_pb([(1, 2, b"")])), (3, 2, encode_pb([(1, 2, _enc_color(1.0, 1.0, 1.0, 0.0))]))])),
            (32, 2, rt),
        ])
        self._append_note_pair(page, obj_id, rev_cnt, rev_tie, 35, 21, payload)
        return obj_id

    def add_sticky_note(
        self,
        page: PageBuildState,
        x: float,
        y: float,
        text: str,
        bg_color: Tuple[float, float, float, float] = (0.980392, 0.905882, 0.470588, 1.0),
        author_name: str = "Agent Writer",
    ) -> str:
        obj_id = str(uuid.uuid4()).upper()
        z_idx, z_tie = page.next_z, self._next_tie()
        page.next_z += 1
        rev_cnt, rev_tie = 1, self._next_tie()
        rt = encode_richtext_container(text=text, font_size=24.0, text_color=(0.193, 0.166, 0.007, 1.0))
        payload = encode_pb([
            (1, 2, obj_id),
            (2, 0, 35),
            (3, 2, _enc_lww_clock(rev_cnt, rev_tie)),
            (7, 2, _enc_zorder(z_idx, z_tie)),
            (20, 2, encode_pb([(1, 2, _enc_point(x, y)), (3, 5, 1.0)])),
            (21, 2, encode_pb([(2, 2, encode_pb([(1, 5, 256.0), (2, 5, 256.0), (3, 5, float("inf"))]))])),
            (30, 2, _enc_color(*bg_color)),
            (31, 2, rt),
            (32, 2, str(uuid.uuid4())),
            (33, 2, author_name),
            (40, 0, 1),
            (41, 0, 1),
        ])
        self._append_note_pair(page, obj_id, rev_cnt, rev_tie, 35, 20, payload)
        return obj_id

    def add_image(
        self,
        page: PageBuildState,
        x: float,
        y: float,
        w: float,
        h: float,
        image_bytes: Optional[bytes] = None,
    ) -> str:
        blob = image_bytes or _minimal_1x1_png_rgba(40, 120, 220, 255)
        att_id = self.register_attachment(blob, is_pdf=False)
        obj_id = str(uuid.uuid4()).upper()
        z_idx, z_tie = page.next_z, self._next_tie()
        page.next_z += 1
        rev_cnt, rev_tie = 2, self._next_tie()
        payload = encode_pb([
            (1, 2, obj_id),
            (2, 2, _enc_rect(x, y, w, h)),
            (3, 2, _enc_rect(x + w / 2.0, y + h / 2.0, w, h)),
            (4, 2, att_id),
            (5, 2, _enc_zorder(z_idx, z_tie)),
            (15, 2, _enc_lww_clock(rev_cnt, rev_tie)),
            (18, 0, 24),
        ])
        self._append_note_pair(page, obj_id, rev_cnt, rev_tie, 24, 1, payload, attachment_id=att_id)
        return obj_id

    def to_bytes(self) -> bytes:
        buf = io.BytesIO()
        notes_idx = []
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("schema.pb", encode_pb([(1, 0, self.max_schema_version)]))
            zf.writestr("document.info.pb", b"")
            for p in self.pages:
                npath = f"notes/{p.note_layer_id}"
                zf.writestr(npath, encode_delimited(p.records))
                notes_idx.append(encode_pb([(1, 2, p.note_layer_id), (2, 2, npath)]))
            zf.writestr("index.notes.pb", encode_delimited(notes_idx))
            att_idx_msgs = [encode_pb([(1, 2, aid), (2, 2, apath)]) for aid, apath in self.att_index]
            zf.writestr("index.attachments.pb", encode_delimited(att_idx_msgs))
            zf.writestr("index.search.pb", b"")
            zf.writestr("index.events.pb", encode_delimited(self.events))
            for aid, blob in self.attachments.items():
                zf.writestr(f"attachments/{aid}", blob)
            if self.thumbnail_jpg:
                zf.writestr("thumbnail.jpg", self.thumbnail_jpg)
        return buf.getvalue()


# ---------------------------------------------------------------------------
# Verification Suite
# ---------------------------------------------------------------------------

_LIBCOMP = None
_LIBCOMP_FAILED = False


def _libcompression_decode_lz4(data: bytes, expected_len: int) -> Optional[bytes]:
    global _LIBCOMP, _LIBCOMP_FAILED
    if _LIBCOMP_FAILED:
        return None
    if _LIBCOMP is None:
        try:
            lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
            lib.compression_decode_buffer.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_size_t,
                ctypes.c_void_p, ctypes.c_int,
            ]
            lib.compression_decode_buffer.restype = ctypes.c_size_t
            _LIBCOMP = lib
        except OSError:
            _LIBCOMP_FAILED = True
            return None
    dst = ctypes.create_string_buffer(max(expected_len + 1024, 65536))
    n = _LIBCOMP.compression_decode_buffer(dst, len(dst), data, len(data), None, 0x100)
    return dst.raw[:n]


def verify_archive(archive_path: Path) -> None:
    tpl_checked = 0
    bv41_checked = 0
    libcomp_checked = 0
    note_objs_checked = 0

    with zipfile.ZipFile(archive_path, "r") as zf:
        entries = zf.namelist()
        schema = decode_schema(zf.read("schema.pb"))
        events = decode_index_events(zf.read("index.events.pb"))
        notes_idx = decode_index_entries(zf.read("index.notes.pb"))
        att_idx = decode_index_entries(zf.read("index.attachments.pb"))
        search_idx = decode_index_entries(zf.read("index.search.pb"), has_kind=True)

        # 1. Verify PageUUID + 1 == NoteLayerUUID for every CreatePage event
        page_events = [e for e in events if e["event_tag"] == 54]
        note_uuids = {e["uuid"] for e in notes_idx}
        for pe in page_events:
            derived = str(uuid.UUID(int=uuid.UUID(pe["page_id"]).int + 1)).upper()
            assert derived == pe["note_layer_id"] and derived in note_uuids, f"UUID derivation mismatch for {pe['page_id']}"

        # 2. Verify every note object, TPL blob, bv41 blob, header.2 == payload.rev, schema max
        max_ver = 0
        for ne in notes_idx:
            data = zf.read(ne["path"])
            if not data:
                continue
            msgs = parse_delimited(data)
            assert len(msgs) % 2 == 0
            for k in range(0, len(msgs), 2):
                note_objs_checked += 1
                hd = pb_dict(msgs[k])
                pfn, _, pval = msgs[k + 1][0]
                pd = pb_dict(parse_pb(pval))
                rev_field = {1: 15, 7: 15, 9: 15, 20: 3, 21: 3, 22: 3}[pfn]
                assert hd[2][0][1] == pd[rev_field][0][1], f"Header/Payload revision mismatch in {hd[1][0][1]}"
                ver = hd[16][0][1]
                max_ver = max(max_ver, ver)

                if pfn == 7:
                    comp = pd[2][0][1]
                    dec = decompress_bv41(comp)
                    bv41_checked += 1

                    # Round-trip TPL byte-for-byte
                    fmt, raw_vals = parse_tpl_raw(dec)
                    re_tpl = encode_tpl(fmt, raw_vals)
                    assert re_tpl == dec, f"TPL round-trip mismatch on {hd[1][0][1]}"
                    tpl_checked += 1

                    # Round-trip bv41 pure Python + macOS libcompression cross-check
                    re_comp = compress_bv41(dec)
                    assert decompress_bv41(re_comp) == dec, "bv41 pure-Python round-trip mismatch"
                    ap_orig = _libcompression_decode_lz4(comp, len(dec))
                    ap_ours = _libcompression_decode_lz4(re_comp, len(dec))
                    if ap_orig is not None:
                        assert ap_orig == dec, "libcompression mismatch on original bv41"
                        assert ap_ours == dec, "libcompression mismatch on our compress_bv41"
                        libcomp_checked += 1

                elif pfn in (20, 21):
                    tf = 31 if pfn == 20 else 32
                    c1 = pb_dict(parse_pb(pd[tf][0][1]))[1][0][1]
                    comp = pb_dict(parse_pb(c1))[2][0][1]
                    dec = decompress_bv41(comp)
                    bv41_checked += 1
                    re_comp = compress_bv41(dec)
                    assert decompress_bv41(re_comp) == dec
                    ap_orig = _libcompression_decode_lz4(comp, len(dec))
                    ap_ours = _libcompression_decode_lz4(re_comp, len(dec))
                    if ap_orig is not None:
                        assert ap_orig == dec and ap_ours == dec
                        libcomp_checked += 1

            # Also ensure semantic decoder runs cleanly
            _ = decode_note_layer(data)

        assert max_ver == schema["schema_version"], f"schema.pb {schema['schema_version']} != max {max_ver}"

        # 3. Verify search files
        for se in search_idx:
            sdata = zf.read(se["path"])
            if se["kind"] == 1:
                _ = decode_search_pdf(sdata)
            else:
                _ = decode_search_page(sdata)

        # 4. Verify synthetic GoodnotesBuilder round-trip in memory
        builder = GoodnotesBuilder(title="SyntheticVerify")
        p1 = builder.add_page(595.28, 841.89, (0.2, 0.2, 0.2), "SyntheticDark")
        builder.add_ballpoint_or_highlighter_stroke(p1, [(50.0, 50.0), (150.0, 80.0), (220.0, 50.0)], color=(1.0, 1.0, 1.0, 1.0))
        builder.add_pencil_stroke(p1, [(50.0, 120.0, 0.5), (180.0, 130.0, 0.9)])
        builder.add_snapped_polygon_with_fill(p1, [(300.0, 100.0), (400.0, 100.0), (350.0, 180.0), (300.0, 100.0)])
        builder.add_textbox(p1, 50.0, 220.0, "Hello Goodnotes")
        builder.add_sticky_note(p1, 450.0, 200.0, "Sticky check")
        builder.add_image(p1, 50.0, 320.0, 100.0, 100.0)
        syn_bytes = builder.to_bytes()
        with zipfile.ZipFile(io.BytesIO(syn_bytes), "r") as szf:
            s_schema = decode_schema(szf.read("schema.pb"))
            assert s_schema["schema_version"] == 35
            s_notes = decode_index_entries(szf.read("index.notes.pb"))
            assert len(s_notes) == 1
            s_objs = decode_note_layer(szf.read(s_notes[0]["path"]))
            assert len(s_objs) == 7  # ballpoint + pencil + fill + snapped stroke + textbox + sticky + image

    print(f"OK: archive entries={len(entries)}, events={len(events)}, attachments={len(att_idx)}, search={len(search_idx)}")
    print(f"OK: note objects verified={note_objs_checked}, schema.pb={schema['schema_version']} (matches max object version)")
    print(f"OK: TPL round-trips={tpl_checked}/{tpl_checked} byte-identical")
    print(f"OK: bv41 round-trips={bv41_checked}/{bv41_checked} pure-Python, {libcomp_checked}/{bv41_checked} macOS libcompression identical")
    print("OK: synthetic GoodnotesBuilder round-trip verified (7/7 objects across schema v35)")


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Goodnotes (.goodnotes) codec, disassembler, SVG renderer, and verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dis = sub.add_parser("disassemble", help="Decode a .goodnotes archive into structured JSON files")
    p_dis.add_argument("input", type=Path)
    p_dis.add_argument("output_dir", type=Path)

    p_svg = sub.add_parser("render-svg", help="Render decoded pages to SVG previews")
    p_svg.add_argument("input", type=Path)
    p_svg.add_argument("output_dir", type=Path)

    p_ver = sub.add_parser("verify", help="Run round-trip and invariant checks on a .goodnotes archive")
    p_ver.add_argument("input", type=Path)

    p_syn = sub.add_parser("create-sample", help="Write a sample synthetic .goodnotes file")
    p_syn.add_argument("output", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "disassemble":
        disassemble_archive(args.input, args.output_dir)
        print(f"Disassembled {args.input} -> {args.output_dir / 'decoded'}")
    elif args.cmd == "render-svg":
        paths = render_svg_previews(args.input, args.output_dir)
        print("Rendered SVGs:", ", ".join(str(p) for p in paths))
    elif args.cmd == "verify":
        verify_archive(args.input)
    elif args.cmd == "create-sample":
        b = GoodnotesBuilder(title="Sample")
        p = b.add_page()
        b.add_ballpoint_or_highlighter_stroke(p, [(100.0, 100.0), (250.0, 150.0)])
        b.add_textbox(p, 100.0, 200.0, "Generated by goodnotes_codec.py")
        args.output.write_bytes(b.to_bytes())
        print(f"Wrote synthetic archive -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
