class OatDexFileOreo:
    def __init__(self, reader, vdex_header):
        super().__init__(reader)
        self.vdex_header = vdex_header
        if vdex_header is not None:
            for i in range(len(vdex_header.dex_checksums)):
                if vdex_header.dex_checksums[i] == self.get_dex_file_checksum():
                    self.dex_header = vdex_header.dex_header_list[i]
                    break

    def get_vdex_header(self):
        return self.vdex_header

    def is_dex_header_external(self):
        return True
