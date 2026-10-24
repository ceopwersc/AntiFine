import ctypes
import os

import pytest

from src.services.filesystem import BoundaryError, contained


@pytest.mark.skipif(os.name != 'nt', reason='Windows short-path aliases')
def test_real_windows_short_path_containment(tmp_path):
    root = tmp_path / 'antifine_workspace_long_name'
    root.mkdir()
    source = root / 'configuration_long_name.tf'
    source.write_text('# synthetic source', encoding='utf-8')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetShortPathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    buffer = ctypes.create_unicode_buffer(32768)
    assert kernel.GetShortPathNameW(str(source), buffer, len(buffer))
    if '~' not in buffer.value:
        pytest.skip('This filesystem does not generate short-path aliases')
    assert contained(root, type(source)(buffer.value)) == source.resolve()
    sibling = tmp_path / 'antifine_workspace_long_name_sibling'
    sibling.mkdir()
    outside = sibling / 'configuration_long_name.tf'
    outside.write_text('# outside authorized workspace', encoding='utf-8')
    assert kernel.GetShortPathNameW(str(outside), buffer, len(buffer))
    with pytest.raises(BoundaryError):
        contained(root, type(source)(buffer.value))
