class BootImageFileSystem:
    def __init__(self, file_system_name: str, provider):
        self.file_list = []
        super().__init__(file_system_name, provider)

    @property
    def header(self):
        return None

    @header.setter
    def header(self, value):
        self._header = value

    @property
    def kernel_file(self):
        return None

    @kernel_file.setter
    def kernel_file(self, value):
        self._kernel_file = value

    @property
    def ramdisk_file(self):
        return None

    @ramdisk_file.setter
    def ramdisk_file(self, value):
        self._ramdisk_file = value

    @property
    def second_stage_file(self):
        return None

    @second_stage_file.setter
    def second_stage_file(self, value):
        self._second_stage_file = value

    def is_valid(self) -> bool:
        bytes = provider.read_bytes(0, BootImageConstants.BOOT_MAGIC_SIZE)
        return bytes == BootImageConstants.BOOT_MAGIC.encode()

    def open(self):
        if not self.header.get_magic().encode() == BootImageConstants.BOOT_MAGIC.encode():
            raise IOException("Invalid Android boot image file!")

        if self.header.get_kernel_size() > 0:
            kernel_file = GFileImpl.from_filename(self, root, BootImageConstants.KERNEL,
                                                    False, self.header.get_kernel_size(), None)
            self.file_list.append(kernel_file)

        if self.header.get_ramdisk_size() > 0:
            ramdisk_file = GFileImpl.from_filename(self, root, BootImageConstants.RAMDISK,
                                                   False, self.header.get_ramdisk_size(), None)
            self.file_list.append(ramdisk_file)

        if self.header.get_second_size() > 0:
            second_stage_file = GFileImpl.from_filename(self, root, BootImageConstants.SECOND_STAGE,
                                                        False, self.header.get_second_size(), None)
            self.file_list.append(second_stage_file)

    def close(self):
        self.kernel_file = None
        self.ramdisk_file = None
        self.second_stage_file = None
        super().close()

    def get_listing(self) -> list:
        if directory is None or directory == root:
            return [file for file in self.file_list]
        else:
            return []

    def get_file_attributes(self, file: GFile):
        if file == kernel_file:
            return FileAttributes.of(FileAttribute.create(FileAttributeType.COMMENT_ATTR,
                                                            "This is the actual KERNEL for the android device. You can analyze this file."))

        elif file == ramdisk_file:
            return FileAttributes.of(FileAttribute.create(FileAttributeType.COMMENT_ATTR,
                                                            "This is a ramdisk, it is a GZIP file containing a CPIO archive."))

        else:
            return None

    def get_byte_provider(self) -> ByteProvider:
        if file in [kernel_file, ramdisk_file, second_stage_file]:
            offset = self.header.get_kernel_offset() if file == kernel_file \
                else (self.header.get_ramdisk_offset() if file == ramdisk_file
                      else self.header.get_second_offset())

            size = self.header.get_kernel_size() if file == kernel_file \
                else (self.header.get_ramdisk_size() if file == ramdisk_file
                      else self.header.get_second_size())
        return ByteProviderWrapper(provider, offset, size)
