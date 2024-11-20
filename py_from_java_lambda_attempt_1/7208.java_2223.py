Here is the translation of the given Java code into Python:

```Python
class OatQuickMethodHeaderOreo:
    SIZE = 16 + QuickMethodFrameInfo.SIZE

    def __init__(self, reader):
        self.vmap_table_offset_ = reader.read_int()
        self.method_info_offset_ = reader.read_int()
        self.frame_info_ = QuickMethodFrameInfo(reader)
        self.code_size_ = reader.read_int()
        self.code_ = reader.read_bytes(self.code_size_)

    @property
    def vmap_table_offset(self):
        return self.vmap_table_offset_

    @property
    def method_info_offset(self):
        return self.method_info_offset_

    @property
    def frame_info(self):
        return self.frame_info_

    @property
    def code_size(self):
        return self.code_size_

    @property
    def code(self):
        return self.code_


class QuickMethodFrameInfo:
    pass  # This class is not defined in the given Java code, so we can't translate it accurately.