Here is the translation of the Java code into Python:

```Python
class YAFFS2Entry:
    def __init__(self):
        self.file_offset = None
        self.header = None
        self.extended_tags = None

    def parse(self, buffer):
        # header
        self.header = YAFFS2Header(buffer[:YAFFS2Constants.HEADER_SIZE])

        # extended tags
        self.extended_tags = YAFFS2ExtendedTags(
            buffer[YAFFS2Constants.DATA_BUFFER_SIZE:YAFFS2Constants.RECORD_SIZE]
        )

    def get_object_id(self):
        return self.extended_tags.get_object_id()

    def is_directory(self):
        return self.header.is_directory()

    def get_checksum(self):
        return self.header.get_checksum()

    def get_name(self):
        return self.header.get_name()

    def get_yst_mode(self):
        return self.header.get_yst_mode()

    def get_yst_u_id(self):
        return self.header.get_yst_u_id()

    def get_yst_g_id(self):
        return self.header.get_yst_g_id()

    def get_yst_atime(self):
        return self.header.get_yst_atime()

    def get_yst_mtime(self):
        return self.header.get_yst_mtime()

    def get_yst_ctime(self):
        return self.header.get_yst_ctime()

    def get_size(self):
        return self.header.get_size()

    def get_equiv_id(self):
        return self.header.get_equiv_id()

    def get_alias_file_name(self):
        return self.header.get_alias_file_name()

    def get_yst_r_dev(self):
        return self.header.get_yst_r_dev()

    def get_win_ctime(self):
        return self.header.get_win_ctime()

    def get_win_atime(self):
        return self.header.get_win_atime()

    def get_win_mtime(self):
        return self.header.get_win_mtime()

    def get_inband_obj_id(self):
        return self.header.get_inband_obj_id()

    def get_inband_is_shrink(self):
        return self.header.get_inband_is_shrink()

    def get_file_size_high(self):
        return self.header.get_file_size_high()

    def get_shadows_object(self):
        return self.header.get_shadows_object()

    def get_is_shrink(self):
        return self.header.get_is_shrink()

    def get_sequence_number(self):
        return self.extended_tags.get_sequence_number()

    def get_chunk_id(self):
        return self.extended_tags.get_chunk_id()

    def get_number_bytes(self):
        return self.extended_tags.get_number_bytes()

    def get_ecc_col_parity(self):
        return self.extended_tags.get_ecc_col_parity()

    def get_ecc_line_parity(self):
        return self.extended_tags.get_ecc_line_parity()

    def get_ecc_line_parity_prime(self):
        return self.extended_tags.get_ecc_line_parity_prime()

    def set_file_offset(self, file_offset):
        self.file_offset = file_offset

    def get_file_offset(self):
        return self.file_offset
```

Note that I've removed the `package` declaration and the license information as they are not relevant to the translation. Also, Python does not have a direct equivalent of Java's `Arrays.copyOfRange()` method, so we simply slice the buffer array in the `parse()` method.