"""Owner-only private storage, including protected Windows DACL inheritance."""
import os
from pathlib import Path
import threading

_secured: set[Path] = set()
_lock = threading.Lock()


def restrict(root: Path):
    with _lock:
        if root in _secured:
            return
        if os.name == "nt":
            import csv
            import ctypes
            from ctypes import wintypes
            import subprocess
            owner = list(csv.reader(subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True).splitlines()))[0][1]
            if not owner.startswith("S-1-"):
                raise OSError("Cannot identify private storage owner")
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
            convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
            convert.restype = wintypes.BOOL
            get_acl = advapi.GetSecurityDescriptorDacl
            get_acl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
            get_acl.restype = wintypes.BOOL
            set_acl = advapi.SetNamedSecurityInfoW
            set_acl.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            set_acl.restype = wintypes.DWORD
            descriptor = ctypes.c_void_p()
            if not convert(f"D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)", 1, ctypes.byref(descriptor), None):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                present, defaulted, acl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
                if not get_acl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
                    raise ctypes.WinError(ctypes.get_last_error())
                error = set_acl(ctypes.create_unicode_buffer(str(root)), 1, 0x80000004, None, None, acl, None)
                if error:
                    raise ctypes.WinError(error)
            finally:
                kernel.LocalFree.argtypes = [ctypes.c_void_p]
                kernel.LocalFree(descriptor)
        else:
            os.chmod(root, 0o700)
        _secured.add(root)
