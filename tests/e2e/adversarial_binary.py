#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Test-only binary mutator for adversarial e2e gates.
#
# `seal` finalizes self_checksum_constants post-link manifests by filling the
# expected hash and code-window length after native layout is known. `patch-*`
# deliberately mutates protected bytes so the sealed binary must stop behaving
# like the unpatched one.

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SC_MAGIC = 0xA7D13C5E9000C3B2
SC_MANIFEST_SIZE = 72
MG_MAGIC = 0x8E21B7C4005AF10D
MG_HEADER_SIZE = 24
MG_RECORD_SIZE = 32

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
S_SYMBOL_STUBS = 0x8
INDIRECT_SYMBOL_MASK = 0x0FFFFFFF

ELF_MACHINE_X86_64 = 62
ELF_MACHINE_AARCH64 = 183
PT_LOAD = 1


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    flags: int = 0


@dataclass
class Section:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    flags: int
    reserved1: int
    reserved2: int


@dataclass
class Manifest:
    offset: int
    region: int
    expected: int
    region_size: int
    seed: int
    expected_hash: int
    target: int
    code_size: int


class Binary:
    def __init__(self, path: Path):
        self.path = path
        self.data = bytearray(path.read_bytes())
        self.kind = ""
        self.arch = ""
        self.segments: list[Segment] = []
        self.sections: list[Section] = []
        self.symbols: list[str] = []
        self.indirect_symbols: list[int] = []
        self.macho_base = 0
        self._parse()

    def _parse(self) -> None:
        if self.data.startswith(b"\x7fELF"):
            self._parse_elf64()
            return
        magic = self.u32(0)
        if magic == 0xFEEDFACF:
            self._parse_macho64()
            return
        raise SystemExit(f"unsupported binary format: {self.path}")

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def put_u32(self, off: int, value: int) -> None:
        struct.pack_into("<I", self.data, off, value & 0xFFFFFFFF)

    def put_u64(self, off: int, value: int) -> None:
        struct.pack_into("<Q", self.data, off, value & 0xFFFFFFFFFFFFFFFF)

    def _parse_elf64(self) -> None:
        if self.data[4] != 2 or self.data[5] != 1:
            raise SystemExit("only little-endian ELF64 is supported")
        self.kind = "elf"
        machine = self.u16(18)
        if machine == ELF_MACHINE_X86_64:
            self.arch = "x86_64"
        elif machine == ELF_MACHINE_AARCH64:
            self.arch = "arm64"
        else:
            self.arch = f"elf-machine-{machine}"

        e_phoff = self.u64(32)
        e_phentsize = self.u16(54)
        e_phnum = self.u16(56)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = (
                struct.unpack_from("<IIQQQQQQ", self.data, off)
            )
            if p_type == PT_LOAD and p_filesz:
                self.segments.append(
                    Segment(
                        name=f"PT_LOAD_{i}",
                        vmaddr=p_vaddr,
                        vmsize=p_memsz,
                        fileoff=p_offset,
                        filesize=p_filesz,
                        flags=p_flags,
                    )
                )

    def _parse_macho64(self) -> None:
        self.kind = "macho"
        (
            _magic,
            cputype,
            _cpusubtype,
            _filetype,
            ncmds,
            _sizeofcmds,
            _flags,
            _reserved,
        ) = struct.unpack_from("<IiiIIIII", self.data, 0)
        if cputype == CPU_TYPE_ARM64:
            self.arch = "arm64"
        elif cputype == CPU_TYPE_X86_64:
            self.arch = "x86_64"
        else:
            self.arch = f"macho-cpu-{cputype}"

        symoff = nsyms = stroff = strsize = None
        indirectsymoff = nindirectsyms = None

        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SEGMENT_64:
                (
                    _cmd,
                    _cmdsize,
                    segname_raw,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    _initprot,
                    nsects,
                    _segflags,
                ) = struct.unpack_from("<II16sQQQQiiII", self.data, off)
                segname = cstr(segname_raw)
                self.segments.append(
                    Segment(segname, vmaddr, vmsize, fileoff, filesize, maxprot)
                )
                sec_off = off + 72
                for _sec in range(nsects):
                    (
                        sect_raw,
                        sec_seg_raw,
                        addr,
                        size,
                        offset,
                        _align,
                        _reloff,
                        _nreloc,
                        flags,
                        reserved1,
                        reserved2,
                        _reserved3,
                    ) = struct.unpack_from("<16s16sQQIIIIIIII", self.data, sec_off)
                    self.sections.append(
                        Section(
                            cstr(sect_raw),
                            cstr(sec_seg_raw),
                            addr,
                            size,
                            offset,
                            flags,
                            reserved1,
                            reserved2,
                        )
                    )
                    sec_off += 80
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from(
                    "<IIII", self.data, off + 8
                )
            elif cmd == LC_DYSYMTAB:
                fields = struct.unpack_from("<18I", self.data, off + 8)
                indirectsymoff, nindirectsyms = fields[12], fields[13]
            off += cmdsize

        file_backed = [seg.vmaddr for seg in self.segments if seg.filesize > 0]
        if file_backed:
            self.macho_base = min(file_backed)

        if symoff is not None and stroff is not None:
            strtab = self.data[stroff : stroff + strsize]
            for i in range(nsyms):
                n_strx = self.u32(symoff + i * 16)
                self.symbols.append(read_str(strtab, n_strx))
        if indirectsymoff is not None:
            for i in range(nindirectsyms):
                self.indirect_symbols.append(self.u32(indirectsymoff + i * 4))

    def write(self) -> None:
        self.path.write_bytes(self.data)

    def segment_for_addr(self, addr: int) -> Segment | None:
        for seg in self.segments:
            end = seg.vmaddr + min(seg.vmsize, seg.filesize)
            if seg.vmaddr <= addr < end:
                return seg
        return None

    def fileoff_for_addr(self, addr: int) -> int | None:
        seg = self.segment_for_addr(addr)
        if not seg:
            return None
        delta = addr - seg.vmaddr
        if delta >= seg.filesize:
            return None
        return seg.fileoff + delta

    def read_addr(self, addr: int, size: int) -> bytes | None:
        off = self.fileoff_for_addr(addr)
        if off is None or off + size > len(self.data):
            return None
        return bytes(self.data[off : off + size])

    def decode_pointer(self, raw: int) -> int:
        if self.fileoff_for_addr(raw) is not None:
            return raw
        if self.kind == "macho" and self.macho_base:
            # Modern arm64 Mach-O files commonly store local data pointers as
            # dyld chained rebase records. For DYLD_CHAINED_PTR_64_REBASE the
            # low 36 bits are the unslid target offset from the image base; the
            # high bits carry chain metadata. Decode that form for post-link
            # manifests without needing symbol names.
            target = raw & ((1 << 36) - 1)
            candidate = self.macho_base + target
            if self.fileoff_for_addr(candidate) is not None:
                return candidate
        return raw

    def find_sc_manifests(self) -> list[Manifest]:
        needle = struct.pack("<Q", SC_MAGIC)
        found: list[Manifest] = []
        start = 0
        while True:
            off = self.data.find(needle, start)
            if off < 0:
                break
            start = off + 1
            if off + SC_MANIFEST_SIZE > len(self.data):
                continue
            version = self.u32(off + 8)
            region_size = self.u32(off + 32)
            if version != 2 or region_size == 0 or region_size > 1 << 20:
                continue
            region = self.decode_pointer(self.u64(off + 16))
            expected = self.decode_pointer(self.u64(off + 24))
            target = self.decode_pointer(self.u64(off + 56))
            code_size = self.decode_pointer(self.u64(off + 64))
            m = Manifest(
                offset=off,
                region=region,
                expected=expected,
                region_size=region_size,
                seed=self.u64(off + 40),
                expected_hash=self.u64(off + 48),
                target=target,
                code_size=code_size,
            )
            if (
                self.fileoff_for_addr(m.region) is not None
                and self.fileoff_for_addr(m.expected) is not None
                and self.fileoff_for_addr(m.target) is not None
                and self.fileoff_for_addr(m.code_size) is not None
            ):
                found.append(m)
        return found

    def macho_stub_offsets(self, wanted: set[str]) -> list[tuple[str, int, int]]:
        if self.kind != "macho" or not self.symbols or not self.indirect_symbols:
            return []
        out: list[tuple[str, int, int]] = []
        for sec in self.sections:
            if (sec.flags & 0xFF) != S_SYMBOL_STUBS or sec.reserved2 == 0:
                continue
            count = sec.size // sec.reserved2
            for i in range(count):
                indirect_index = sec.reserved1 + i
                if indirect_index >= len(self.indirect_symbols):
                    continue
                sym_index = self.indirect_symbols[indirect_index]
                sym_index &= INDIRECT_SYMBOL_MASK
                if sym_index >= len(self.symbols):
                    continue
                name = self.symbols[sym_index]
                if name in wanted:
                    out.append((name, sec.offset + i * sec.reserved2, sec.reserved2))
        return out


def cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def read_str(raw: bytes, off: int) -> str:
    if off <= 0 or off >= len(raw):
        return ""
    end = raw.find(b"\0", off)
    if end < 0:
        end = len(raw)
    return raw[off:end].decode("utf-8", "replace")


def hash_step(h: int, b: int) -> int:
    h ^= b
    h = (h * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 32
    h = (h * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
    h ^= h >> 29
    return h & 0xFFFFFFFFFFFFFFFF


def hash_bytes(blob: bytes, seed: int) -> int:
    h = seed & 0xFFFFFFFFFFFFFFFF
    for b in blob:
        h = hash_step(h, b)
    return h


def resign_macho(binary: "Binary", path: Path) -> None:
    """Re-sign a modified Mach-O so the kernel will run it.

    Sealing rewrites bytes in __DATA, which invalidates any existing code
    signature.  On arm64 macOS the kernel SIGKILLs a binary whose signature no
    longer matches its pages BEFORE a single instruction executes — so without
    this step a freshly sealed binary just dies with "killed" and the runtime
    self-check never even runs.  Ad-hoc re-sign to make it launchable again.
    """
    if binary.kind != "macho":
        return
    codesign = shutil.which("codesign")
    if not codesign:
        return
    result = subprocess.run(
        [codesign, "--force", "--sign", "-", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"warning: codesign failed after seal ({result.stderr.strip()}); "
            f"re-sign {path} manually or it will be killed at launch",
            file=sys.stderr,
        )


def seal(path: Path, window: int) -> int:
    binary = Binary(path)
    manifests = binary.find_sc_manifests()
    sealed = 0
    for m in manifests:
        if m.seed == 0 and m.expected_hash == 0:
            continue
        region = binary.read_addr(m.region, m.region_size)
        target_seg = binary.segment_for_addr(m.target)
        target_off = binary.fileoff_for_addr(m.target)
        expected_off = binary.fileoff_for_addr(m.expected)
        code_size_off = binary.fileoff_for_addr(m.code_size)
        if (
            region is None
            or target_seg is None
            or target_off is None
            or expected_off is None
            or code_size_off is None
        ):
            continue
        seg_end_addr = target_seg.vmaddr + target_seg.filesize
        code_len = max(0, min(window, seg_end_addr - m.target))
        if code_len <= 0:
            continue
        code = bytes(binary.data[target_off : target_off + code_len])
        expected = hash_bytes(code, hash_bytes(region, m.seed))
        binary.put_u64(expected_off, expected)
        binary.put_u32(code_size_off, code_len)
        binary.put_u64(m.offset + 40, 0)
        binary.put_u64(m.offset + 48, 0)
        sealed += 1
    if sealed:
        binary.write()
        resign_macho(binary, path)
    print(f"sealed self-check manifests={sealed} binary={path}")
    return 0 if sealed else 1


def postlink_oracle_findings(binary: Binary) -> list[str]:
    findings: list[str] = []
    for m in binary.find_sc_manifests():
        if m.seed != 0 or m.expected_hash != 0:
            findings.append(
                f"self-check manifest at file+0x{m.offset:x} retains "
                "seed/expected_hash"
            )

    needle = struct.pack("<Q", MG_MAGIC)
    start = 0
    while True:
        off = binary.data.find(needle, start)
        if off < 0:
            break
        start = off + 1
        if off + MG_HEADER_SIZE > len(binary.data):
            continue
        version = binary.u32(off + 8)
        count = binary.u32(off + 12)
        region_size = binary.u32(off + 16)
        if version != 2 or count == 0 or count > 1024 or region_size > 1 << 20:
            continue
        total_size = MG_HEADER_SIZE + count * MG_RECORD_SIZE
        if off + total_size > len(binary.data):
            continue
        for i in range(count):
            rec = off + MG_HEADER_SIZE + i * MG_RECORD_SIZE
            region = binary.decode_pointer(binary.u64(rec))
            expected = binary.decode_pointer(binary.u64(rec + 8))
            if (
                binary.fileoff_for_addr(region) is None
                or binary.fileoff_for_addr(expected) is None
            ):
                continue
            seed = binary.u64(rec + 16)
            expected_hash = binary.u64(rec + 24)
            if seed != 0 or expected_hash != 0:
                findings.append(
                    f"mutual-guard manifest at file+0x{off:x} node={i} "
                    "retains seed/expected_hash"
                )
    return findings


def assert_no_postlink_oracles(path: Path) -> int:
    binary = Binary(path)
    findings = postlink_oracle_findings(binary)
    for finding in findings:
        print(f"FAIL {finding}", file=sys.stderr)
    if findings:
        return 1
    print(f"OK no retained post-link oracle data binary={path}")
    return 0


def patch_selfcheck_code(path: Path) -> int:
    binary = Binary(path)
    manifests = binary.find_sc_manifests()
    if not manifests:
        print("no self-check manifests to patch", file=sys.stderr)
        return 1
    m = manifests[0]
    target_off = binary.fileoff_for_addr(m.target)
    if target_off is None:
        print("manifest target is not file-backed", file=sys.stderr)
        return 1
    if binary.arch == "arm64":
        # ARM64 NOP: 1f 20 03 d5
        patch_off = target_off - (target_off % 4)
        binary.data[patch_off : patch_off + 4] = b"\x1f\x20\x03\xd5"
    elif binary.arch == "x86_64":
        binary.data[target_off] = 0x90
    else:
        print(f"unsupported architecture for code patch: {binary.arch}", file=sys.stderr)
        return 77
    binary.write()
    print(f"patched sealed code byte at manifest target=0x{m.target:x}")
    return 0


def patch_rdtscp_sequences(binary: Binary) -> int:
    # lfence; rdtscp; lfence
    sequence = b"\x0f\xae\xe8\x0f\x01\xf9\x0f\xae\xe8"
    count = 0
    start = 0
    while True:
        off = binary.data.find(sequence, start)
        if off < 0:
            break
        binary.data[off : off + len(sequence)] = b"\x90" * len(sequence)
        count += 1
        start = off + len(sequence)
    # Some assemblers may separate the fences. Patch bare RDTSCP too, after the
    # full sequence pass so it cannot hide a sequence match.
    bare = b"\x0f\x01\xf9"
    start = 0
    while True:
        off = binary.data.find(bare, start)
        if off < 0:
            break
        binary.data[off : off + len(bare)] = b"\x90" * len(bare)
        count += 1
        start = off + len(bare)
    return count


def patch_arm64_import_stub(binary: Binary, name: str, off: int, size: int) -> int:
    if size < 8:
        return 0
    # mov x0, #0; ret; nop...
    patch = bytearray(b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6")
    while len(patch) < size:
        patch += b"\x1f\x20\x03\xd5"
    binary.data[off : off + size] = patch[:size]
    print(f"patched {name} stub at file+0x{off:x} size={size}")
    return 1


def patch_timing(path: Path) -> int:
    binary = Binary(path)
    patched = 0
    if binary.arch == "x86_64":
        patched += patch_rdtscp_sequences(binary)
    if binary.kind == "macho" and binary.arch == "arm64":
        wanted = {"_mach_absolute_time", "_clock_gettime"}
        for name, off, size in binary.macho_stub_offsets(wanted):
            patched += patch_arm64_import_stub(binary, name, off, size)
    if not patched:
        print(
            f"no supported timing primitive found in {path} "
            f"(format={binary.kind} arch={binary.arch})",
            file=sys.stderr,
        )
        return 77
    binary.write()
    print(f"patched timing primitives={patched} binary={path}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_seal = sub.add_parser("seal")
    p_seal.add_argument("binary", type=Path)
    p_seal.add_argument("--window", type=int, default=262144)

    p_code = sub.add_parser("patch-selfcheck-code")
    p_code.add_argument("binary", type=Path)

    p_timing = sub.add_parser("patch-timing")
    p_timing.add_argument("binary", type=Path)

    p_oracles = sub.add_parser("assert-no-postlink-oracles")
    p_oracles.add_argument("binary", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "seal":
        return seal(args.binary, args.window)
    if args.cmd == "patch-selfcheck-code":
        return patch_selfcheck_code(args.binary)
    if args.cmd == "patch-timing":
        return patch_timing(args.binary)
    if args.cmd == "assert-no-postlink-oracles":
        return assert_no_postlink_oracles(args.binary)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
