Here is the translation of the given Java code into Python:

```Python
class ExceptionHandlerFrameHeader:
    def __init__(self):
        self.eh_frame_hdr_struct = {"eh_frame_header_version": None,
                                     "eh_frame_pointer_encoding": None,
                                     "eh_frame_description_entry_count": None,
                                     "eh_handler_table_encoding": None}

    def add_to_data_type_manager(self, prog):
        dt_manager = prog.get_data_type_manager()
        dt_manager.add_data_type(self.eh_frame_hdr_struct)

    def create(self, addr):
        if addr is None:
            return
        data_cmd = CreateStructureCmd(self.eh_frame_hdr_struct, addr)
        data_cmd.apply_to(prog)
        comment_cmd = SetCommentCmd(addr, "Exception Handler Frame Header")
        comment_cmd.apply_to(prog)
        self.eh_version = prog.get_memory().get_byte(addr) & 0xFF
        self.eh_FramePtrEncoding = prog.get_memory().get_byte(addr + 1) & 0xFF
        self.eh_FrameDescEntryCntEncoding = prog.get_memory().get_byte(addr + 2) & 0xFF
        self.eh_FrameTableEncoding = prog.get_memory().get_byte(addr + 3) & 0xFF

    def get_length(self):
        return len(self.eh_frame_hdr_struct)

    def get_eh_frame_version(self):
        return self.eh_version

    def get_eh_frame_desc_entry_cnt_encoding(self):
        return self.eh_FrameDescEntryCntEncoding

    def get_eh_frame_ptr_encoding(self):
        return self.eh_FramePtrEncoding

    def get_eh_frame_table_encoding(self):
        return self.eh_FrameTableEncoding
```

Note: This Python code does not exactly translate the given Java code. It is a simplified version of it, as some parts are missing (like TaskMonitor and AddressOutOfBoundsException).