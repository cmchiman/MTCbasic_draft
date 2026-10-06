"""Measurement boundaries are explicit; unavailable memory is never zero."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
from time import perf_counter_ns, process_time_ns
import tracemalloc


def timed_call(function, *args, **kwargs):
    started = perf_counter_ns()
    result = function(*args, **kwargs)
    return result, perf_counter_ns() - started


def rss_bytes():
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong)] + [
                (name, ctypes.c_size_t) for name in
                ("peak", "working", "qpp", "qp", "qnpp", "qnp", "page", "peakpage")]
        try:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
            info = Counters()
            info.cb = ctypes.sizeof(info)
            if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(info), info.cb):
                return int(info.working)
        except (OSError, AttributeError):
            pass
        return None
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            return int(handle.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError, AttributeError):
        return None


@contextmanager
def measure_resources():
    """Dedicated measurement only: refuses to reset an existing tracer."""
    if tracemalloc.is_tracing():
        raise RuntimeError("resource measurement requires ownership of tracemalloc")
    metrics = {}
    tracemalloc.start()
    started, cpu = perf_counter_ns(), process_time_ns()
    try:
        yield metrics
    finally:
        metrics.update(wall_ns=perf_counter_ns()-started, cpu_ns=process_time_ns()-cpu,
                       python_peak_bytes=tracemalloc.get_traced_memory()[1],
                       rss_snapshot_bytes=rss_bytes())
        tracemalloc.stop()


def serialized_size(payload):
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("measure serialized bytes, not Python object overhead")
    return memoryview(payload).nbytes
