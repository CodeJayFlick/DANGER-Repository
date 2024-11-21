Here is the translation of the given Java code into equivalent Python:

```Python
import win32api
from collections import ArrayList

class ToolhelpUtil:
    class Snapshot:
        def __init__(self, handle):
            self.cleanable = None  # No direct equivalent in Python
            self.handle = handle

        def get_items(self, new_struct, first, next):
            items = []
            entry = new_struct()
            while True:
                if not first(entry): break
                items.append(entry)
                entry = new_struct()
            return items

        def get_processes(self):
            return self.get_items(lambda: PROCESSENTRY32W(), lambda x, y: win32api.Process32FirstW(x), lambda x, y: win32api.Process32NextW(y))

        def get_threads(self):
            return self.get_items(lambda: THREADENTRY32(), lambda x, y: win32api.Thread32First(x), lambda x, y: win32api.Thread32Next(y))


    class SnapshotFlags:
        HEAPLIST = 0x0001
        PROCESS = 0x0010
        THREAD = 0x0040
        MODULE = 0x0020
        MODULE32 = 0x0200
        ALL = 0xFFFF
        INHERIT = 0x8000

    def create_snapshot(flags, process_id):
        dw_flags = flags.get_bitmask()
        dw_pid = process_id
        h_snap = win32api.CreateToolhelp32Snapshot(dw_flags, dw_pid)
        if not h_snap:
            raise Exception(win32api.GetLastError())
        return Snapshot(h_snap)

class PROCESSENTRY32W:
    pass

class THREADENTRY32:
    pass


# Usage example:

flags = ToolhelpUtil.SnapshotFlags.HEAPLIST | ToolhelpUtil.SnapshotFlags.PROCESS
snap = ToolhelpUtil.create_snapshot(flags, 1234)
processes = snap.get_processes()
threads = snap.get_threads()

```

Please note that Python does not have direct equivalents for Java's `BiFunction` and `Supplier`. The equivalent in this code is achieved using lambda functions.