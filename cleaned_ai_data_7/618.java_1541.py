class DbgListAvailableProcessesCommand:
    def __init__(self):
        self.snap = None

    def complete(self, pending=None) -> list[tuple[int, str]]:
        result = []
        if self.snap is not None:
            for proc in self.snap.get_processes():
                pid = int(proc.th32_process_id)
                name = bytes(proc.sz_exe_file).decode('utf-8')
                exe = name
                result.append((pid, exe))
        return result

    def invoke(self):
        import toolhelp
        from ghidra_comm.util import BitmaskSet
        self.snap = toolhelp.create_snapshot(BitmaskSet.of(toolhelp.SnapshotFlags.PROCESS | toolhelp.SnapshotFlags.THREAD), 0)
