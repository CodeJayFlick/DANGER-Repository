class DummySymbolServer:
    def __init__(self, dummy_payload: bytes = None, return_compressed_filenames=False):
        self.dummy_payload = dummy_payload if dummy_payload else b''
        self.return_compressed_filenames = return_compressed_filenames

    @property
    def name(self) -> str:
        return "dummy"

    def is_valid(self, monitor=None) -> bool:
        return True

    def exists(self, filename: str, monitor=None) -> bool:
        return True

    def find(self, pdb_info: dict, find_options: set = None, monitor=None) -> list:
        name = pdb_info.get('name')
        if self.return_compressed_filenames:
            name = f"{name[:-1]}_"
        sym_loc = {'filename': name, 'symbol_server': self, 'pdb_info': pdb_info}
        return [sym_loc]

    def get_file_stream(self, filename: str) -> bytes:
        baos = io.BytesIO()
        baos.write(self.dummy_payload)
        return baos.getvalue()

    @property
    def file_location(self, filename: str):
        return f"dummy-{filename}"

    def is_local(self) -> bool:
        return False

import io
