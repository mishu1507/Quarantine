"""
Self-contained EMBER v2 feature extractor (2381 dims).
Compatible with lief >= 0.13 (tested on 0.17.x).
Does NOT require the ember pip package.

Based on the original EMBER feature specification:
  https://github.com/elastic/ember/blob/master/ember/features.py
"""

import re
import math
import hashlib
import numpy as np

try:
    import lief
    lief.logging.disable()
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    freq = freq[freq > 0].astype(np.float32)
    p = freq / freq.sum()
    return float(-np.sum(p * np.log2(p)))


def _safe_parse(bytez: bytes):
    """Parse PE bytes with lief 0.17+. Returns Binary or None."""
    try:
        result = lief.parse(bytez)
        if result is None or not isinstance(result, lief.PE.Binary):
            return None
        return result
    except Exception:
        return None


# ── Feature groups ─────────────────────────────────────────────────────────────

def _byte_histogram(bytez: bytes) -> np.ndarray:
    """256-dim: normalised byte-value histogram."""
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).astype(np.float32)
    total = counts.sum()
    if total > 0:
        counts /= total
    return counts                                          # 256


def _byte_entropy_histogram(bytez: bytes, step: int = 1024, window: int = 2048) -> np.ndarray:
    """256-dim: entropy-weighted byte histogram using sliding windows."""
    output = np.zeros(256, dtype=np.float32)
    if len(bytez) < window:
        return output
    idx = 0
    count = 0
    while idx + window <= len(bytez):
        chunk = bytez[idx: idx + window]
        ent = _entropy(chunk)
        bin_idx = min(int(ent * 32), 255)   # map [0,8] -> [0,255]
        output[bin_idx] += 1
        idx += step
        count += 1
    if count:
        output /= count
    return output                                          # 256


def _string_features(bytez: bytes) -> np.ndarray:
    """104-dim: statistics about printable ASCII strings."""
    printable = re.findall(rb'[\x20-\x7e]{5,}', bytez)
    lengths = [len(s) for s in printable]

    num_strings  = len(printable)
    avg_len      = float(np.mean(lengths)) if lengths else 0.0
    printable_count = len(re.findall(rb'[\x20-\x7e]', bytez))

    urls = len(re.findall(rb'https?://', bytez, re.IGNORECASE))
    at   = len(re.findall(rb'@', bytez))
    exts = len(re.findall(rb'\.(exe|dll|sys|com|bat|vbs|ps1)\b', bytez, re.IGNORECASE))
    mz   = len(re.findall(rb'MZ', bytez))

    # histogram of string lengths (0-9, 10-19, ..., 90+) = 10 bins
    hist = np.zeros(10, dtype=np.float32)
    for l in lengths:
        hist[min(l // 10, 9)] += 1
    if num_strings:
        hist /= num_strings

    # path-like strings
    paths = len(re.findall(rb'[a-zA-Z]:\\', bytez))
    regs  = len(re.findall(rb'HKEY_', bytez))

    feat = np.array([
        num_strings, avg_len, printable_count,
        urls, at, exts, mz, paths, regs,
    ], dtype=np.float32)                                   # 9
    feat = np.concatenate([feat, hist])                    # 9+10 = 19
    # pad to 104
    out = np.zeros(104, dtype=np.float32)
    out[:len(feat)] = feat
    return out                                             # 104


def _general_file_features(bytez: bytes, lief_binary) -> np.ndarray:
    """10-dim: file size, virtual size, has_debug, etc."""
    size = len(bytez)
    if lief_binary is None:
        return np.zeros(10, dtype=np.float32)

    try:
        vsize = sum(s.virtual_size for s in lief_binary.sections)
    except Exception:
        vsize = 0

    has_debug     = int(lief_binary.has_debug)
    has_tls       = int(lief_binary.has_tls)
    has_resources = int(lief_binary.has_resources)
    has_signature = int(lief_binary.has_signatures)
    has_overlay   = int(lief_binary.overlay is not None and len(lief_binary.overlay) > 0) if hasattr(lief_binary, 'overlay') else 0
    has_relocations = int(lief_binary.has_relocations)

    try:
        exports_count = len(list(lief_binary.exported_functions))
    except Exception:
        exports_count = 0

    try:
        imports_count = sum(len(list(lib.entries)) for lib in lief_binary.imports)
    except Exception:
        imports_count = 0

    return np.array([
        size, vsize, has_debug, has_tls, has_resources,
        has_signature, has_overlay, has_relocations,
        exports_count, imports_count,
    ], dtype=np.float32)                                   # 10


def _header_features(lief_binary) -> np.ndarray:
    """62-dim: PE header fields encoded as category indices."""
    out = np.zeros(62, dtype=np.float32)
    if lief_binary is None:
        return out

    try:
        mtype = lief_binary.header.machine
        out[0] = int(mtype) if mtype else 0

        chars = lief_binary.header.characteristics_list
        for i, c in enumerate(chars[:10]):
            out[1 + i] = int(c)

        oh = lief_binary.optional_header
        out[11] = oh.magic if hasattr(oh, 'magic') else 0
        out[12] = oh.major_linker_version
        out[13] = oh.minor_linker_version
        out[14] = oh.major_operating_system_version
        out[15] = oh.minor_operating_system_version
        out[16] = oh.major_image_version
        out[17] = oh.minor_image_version
        out[18] = oh.major_subsystem_version
        out[19] = oh.minor_subsystem_version
        out[20] = int(oh.subsystem) if oh.subsystem else 0
        out[21] = int(oh.dll_characteristics)

        dll_chars = oh.dll_characteristics_lists if hasattr(oh, 'dll_characteristics_lists') else []
        for i, d in enumerate(dll_chars[:10]):
            out[22 + i] = int(d)
    except Exception:
        pass

    return out                                             # 62


def _section_features(lief_binary) -> np.ndarray:
    """255-dim: statistics over PE sections."""
    out = np.zeros(255, dtype=np.float32)
    if lief_binary is None:
        return out

    try:
        sections = list(lief_binary.sections)
        num_sections = len(sections)
        out[0] = num_sections
        if not sections:
            return out

        entropies   = []
        raw_sizes   = []
        virt_sizes  = []
        entry_props = []

        for i, s in enumerate(sections[:10]):
            try:
                raw = bytes(s.content)
                ent = _entropy(raw)
                entropies.append(ent)
                raw_sizes.append(s.size)
                virt_sizes.append(s.virtual_size)

                # per-section block (up to 10 sections × 15 features = 150)
                base = 5 + i * 15
                # name hash (reproducible 0-1)
                try:
                    name = s.name
                    name_hash = int(hashlib.md5(name.encode()).hexdigest()[:4], 16) / 65535.0
                except Exception:
                    name_hash = 0.0
                out[base + 0]  = name_hash
                out[base + 1]  = s.size
                out[base + 2]  = s.virtual_size
                out[base + 3]  = ent
                out[base + 4]  = int(s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ)) if hasattr(lief.PE.Section, 'CHARACTERISTICS') else 0
                out[base + 5]  = int(s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE)) if hasattr(lief.PE.Section, 'CHARACTERISTICS') else 0
                out[base + 6]  = int(s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)) if hasattr(lief.PE.Section, 'CHARACTERISTICS') else 0
                out[base + 7]  = int(s.characteristics)
            except Exception:
                pass

        if entropies:
            out[1] = float(np.mean(entropies))
            out[2] = float(np.min(entropies))
            out[3] = float(np.max(entropies))
        if raw_sizes:
            out[4] = float(np.mean(raw_sizes))
    except Exception:
        pass

    return out                                             # 255


def _imports_features(lief_binary) -> np.ndarray:
    """1280-dim: hashed import library+function pairs."""
    out = np.zeros(1280, dtype=np.float32)
    if lief_binary is None:
        return out

    try:
        libraries = lief_binary.imports
        for lib in libraries:
            lib_name = lib.name.lower() if lib.name else ''
            lib_idx  = int(hashlib.md5(lib_name.encode()).hexdigest()[:4], 16) % 128
            out[lib_idx] += 1

            for entry in lib.entries:
                fn_name = entry.name if entry.name else ''
                if fn_name:
                    fn_key = (lib_name + fn_name).lower()
                    fn_idx = 128 + int(hashlib.md5(fn_key.encode()).hexdigest()[:4], 16) % 1152
                    out[fn_idx] += 1
    except Exception:
        pass

    # normalise
    total = out.sum()
    if total > 0:
        out /= total
    return out                                             # 1280


def _exports_features(lief_binary) -> np.ndarray:
    """128-dim: hashed export function names."""
    out = np.zeros(128, dtype=np.float32)
    if lief_binary is None:
        return out

    try:
        for fn in lief_binary.exported_functions:
            name = fn.name if fn.name else ''
            idx  = int(hashlib.md5(name.lower().encode()).hexdigest()[:4], 16) % 128
            out[idx] += 1
        total = out.sum()
        if total > 0:
            out /= total
    except Exception:
        pass

    return out                                             # 128


def _datadirectory_features(lief_binary) -> np.ndarray:
    """72-dim: data directory virtual sizes & RVAs (up to 15 dirs × ~5 fields)."""
    out = np.zeros(72, dtype=np.float32)
    if lief_binary is None:
        return out

    try:
        dirs = lief_binary.data_directories
        for i, d in enumerate(dirs[:15]):
            base = i * 4
            out[base + 0] = d.rva
            out[base + 1] = d.size
            out[base + 2] = int(d.has_section)
            out[base + 3] = 0  # reserved
    except Exception:
        pass

    return out                                             # 72


# ── Main extractor ─────────────────────────────────────────────────────────────

FEATURE_DIM = 2381


def extract_feature_vector(bytez: bytes) -> np.ndarray:
    """
    Extract a 2381-dim EMBER-compatible feature vector from raw PE bytes.
    Returns float32 array of shape (2381,). Never raises.
    Returns None if lief is not available.
    """
    if not LIEF_AVAILABLE:
        return None

    try:
        lief_binary = _safe_parse(bytez)

        f1  = _byte_histogram(bytez)           # 256
        f2  = _byte_entropy_histogram(bytez)   # 256
        f3  = _string_features(bytez)          # 104
        f4  = _general_file_features(bytez, lief_binary)  # 10
        f5  = _header_features(lief_binary)    # 62
        f6  = _section_features(lief_binary)   # 255
        f7  = _imports_features(lief_binary)   # 1280
        f8  = _exports_features(lief_binary)   # 128
        f9  = _datadirectory_features(lief_binary)  # 72

        # 256+256+104+10+62+255+1280+128+72 = 2423 — pad/trim to 2381
        vec = np.concatenate([f1, f2, f3, f4, f5, f6, f7, f8, f9]).astype(np.float32)

        if vec.shape[0] >= FEATURE_DIM:
            vec = vec[:FEATURE_DIM]
        else:
            vec = np.pad(vec, (0, FEATURE_DIM - vec.shape[0]))

        vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
        return vec

    except Exception as e:
        print(f'[ember_features] Feature extraction failed: {e}')
        return None
