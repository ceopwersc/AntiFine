"""OS-enforced per-child memory/CPU budgets, in addition to parent wall timeouts."""
import os

_job = None


def enforce():
    global _job
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (6, 8))
        return
    import ctypes
    from ctypes import wintypes
    size = ctypes.c_size_t
    class Basic(ctypes.Structure):
        _fields_ = [("process_time",ctypes.c_int64),("job_time",ctypes.c_int64),("flags",wintypes.DWORD),("min_working",size),("max_working",size),("active",wintypes.DWORD),("affinity",size),("priority",wintypes.DWORD),("scheduling",wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name,ctypes.c_uint64) for name in ("read_ops","write_ops","other_ops","read_bytes","write_bytes","other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic",Basic),("io",IO),("process_memory",size),("job_memory",size),("peak_process",size),("peak_job",size)]
    kernel = ctypes.WinDLL("kernel32",use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p,wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE,wintypes.HANDLE]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    _job = kernel.CreateJobObjectW(None,None)
    limits = Extended()
    limits.basic.flags = 0x100 | 0x8 | 0x2
    limits.basic.active = 1
    limits.basic.process_time = 6 * 10_000_000
    limits.process_memory = 512 * 1024 * 1024
    if not _job or not kernel.SetInformationJobObject(_job,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(_job,kernel.GetCurrentProcess()):
        raise ctypes.WinError(ctypes.get_last_error())
