import ctypes

class DebugClientImpl4:
    def __init__(self, jna_client):
        self.jna_client = jna_client
        super().__init__(jna_client)

    def open_dump_file_wide(self, file_name: str) -> None:
        ull_file_handle = 0x00000000FFFFFFFF
        result = ctypes.windll.user32.OpenDumpFileWideW(file_name.encode('utf-16le'), ull_file_handle)
        if not result:
            raise Exception("OpenDumpFileWide failed")
