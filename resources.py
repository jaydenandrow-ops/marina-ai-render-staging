"""Small dependency-free Windows memory guard."""
from __future__ import annotations

import ctypes
import os


def memory_status() -> dict[str, int | float | None]:
    if os.name != "nt":
        return {"available_bytes": None, "total_bytes": None, "used_percent": None}

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {"available_bytes": None, "total_bytes": None, "used_percent": None}
    return {"available_bytes": int(status.ullAvailPhys), "total_bytes": int(status.ullTotalPhys),
            "used_percent": int(status.dwMemoryLoad)}
