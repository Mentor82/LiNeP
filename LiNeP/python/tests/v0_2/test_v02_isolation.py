"""Tests ensuring LiNeP V0.2 pure-Python isolation and top-level lazy loading."""

import subprocess
import sys


def test_pure_v02_import_loads_no_native_or_cffi():
    """Verify in a clean Python process that importing linep.v0_2 touches ZERO native libraries."""
    code = """
import sys
import linep.v0_2
assert 'linep._cabi' not in sys.modules, '_cabi should not be loaded!'
assert 'cffi' not in sys.modules, 'cffi should not be loaded!'
assert linep.v0_2.LINEP_V02_MAGIC == 0x504E4C32
print('OK')
"""
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert res.returncode == 0, f"Import isolation failed: {res.stderr}"
    assert "OK" in res.stdout


def test_top_level_import_is_lazy():
    """Verify in a clean Python process that import linep does not eagerly load native _cabi."""
    code = """
import sys
import linep
assert 'linep._cabi' not in sys.modules, '_cabi should not be eagerly loaded by import linep!'
assert 'cffi' not in sys.modules, 'cffi should not be eagerly loaded by import linep!'
assert linep.__version__ == '0.2.0'
# Accessing pure Python constants also does not trigger native loading
assert linep.MsgType.HEARTBEAT == 1
assert 'linep._cabi' not in sys.modules, 'Constants should not load native library!'
print('OK')
"""
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert res.returncode == 0, f"Top-level lazy import failed: {res.stderr}"
    assert "OK" in res.stdout


def test_v01_subpackage_explicit_import():
    """Verify that linep.v0_1 can be imported explicitly."""
    from linep.v0_1 import MsgType, HeaderFlags, ErrorCode
    assert MsgType.TASK == 0x10
    assert HeaderFlags.ACK_REQUIRED == 0x02
    assert ErrorCode.PROTOCOL_ERROR == 1000
