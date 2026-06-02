"""
compat.py - Patches lief 0.17+ and numpy 2.x so ember 0.1.0 works cleanly.

Problems fixed:
  1. lief 0.9 exception names (bad_format, pe_error, etc.) removed in lief 0.13+
  2. np.int / np.float / np.complex / np.bool aliases removed in numpy 2.0

Import BEFORE importing ember.
"""
import warnings

# ── NumPy 2.x compatibility ───────────────────────────────────────────────────
import numpy as np

# np.int / np.float / np.bool / np.complex were removed in NumPy 2.0.
# np.object / np.str still exist but are deprecated — DON'T touch those.
_NP_REMOVED = {
    'int':     np.int64,
    'float':   np.float64,
    'complex': np.complex128,
    'bool':    np.bool_,
}
with warnings.catch_warnings():
    warnings.simplefilter('ignore')   # suppress FutureWarning during the probe
    for _alias, _dtype in _NP_REMOVED.items():
        try:
            getattr(np, _alias)       # already exists — leave it alone
        except AttributeError:
            setattr(np, _alias, _dtype)   # truly missing — add it back


# ── lief 0.17 compatibility ───────────────────────────────────────────────────
import lief  # noqa: E402
lief.logging.disable()

class _LiefError(Exception):
    """Dummy stand-in for old lief exception classes removed in lief 0.13+."""

_OLD_LIEF_ERRORS = [
    'bad_format', 'bad_file', 'pe_error', 'parser_error',
    'read_out_of_bound', 'conversion_error', 'not_implemented',
    'not_supported', 'corrupted', 'not_found', 'integrity_error',
    'building_error', 'type_error', 'value_error',
]
for _name in _OLD_LIEF_ERRORS:
    if not hasattr(lief, _name):
        setattr(lief, _name, _LiefError)
