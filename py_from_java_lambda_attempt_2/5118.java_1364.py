Here is the translation of the given Java code into equivalent Python:

```Python
class ImageCor20Header:
    def __init__(self):
        self.cb = 0
        self.major_runtime_version = 0
        self.minor_runtime_version = 0
        self.metadata = None
        self.flags = 0
        self.entry_point_token = 0
        self.entry_point_va = None
        self.resources = None
        self.strong_name_signature = None
        self.code_manager_table = None
        self.vtable_fixups = None
        self.export_address_table_jumps = None
        self.managed_native_header = None

    @staticmethod
    def create_image_cor20_header(reader, index, nt_header):
        image_cor20_header = ImageCor20Header()
        image_cor20_header.init_IMAGE_COR20_HEADER(reader, index, nt_header)
        return image_cor20_header

    def init_IMAGE_COR20_HEADER(self, reader, index, nt_header):
        orig_index = reader.tell()
        reader.seek(index)

        self.cb = reader.read_int()
        self.major_runtime_version = reader.read_short()
        self.minor_runtime_version = reader.read_short()
        self.metadata = CliMetadataDirectory.create_cli_metadata_directory(nt_header, reader)
        self.flags = reader.read_int()
        self.entry_point_token = reader.read_int()
        self.resources = DefaultDataDirectory.create_default_data_directory(nt_header, reader)
        self.strong_name_signature = DefaultDataDirectory.create_default_data_directory(nt_header, reader)
        self.code_manager_table = DefaultDataDirectory.create_default_data_directory(nt_header, reader)
        self.vtable_fixups = DefaultDataDirectory.create_default_data_directory(nt_header, reader)
        self.export_address_table_jumps = DefaultDataDirectory.create_default_data_directory(nt_header, reader)
        self.managed_native_header = DefaultDataDirectory.create_default_data_directory(nt_header, reader)

        reader.seek(orig_index)

    def parse(self):
        success = True

        if not self.metadata.parse():
            success = False
        if not self.resources.parse():
            success = False
        if not self.strong_name_signature.parse():
            success = False
        if not self.code_manager_table.parse():
            success = False
        if not self.vtable_fixups.parse():
            success = False
        if not self.export_address_table_jumps.parse():
            success = False
        if not self.managed_native_header.parse():
            success = False

        return success

    def markup(self, program, is_binary, monitor, log, nt_header):
        if not self.metadata.has_parsed_correctly():
            return

        self.metadata.markup(program, is_binary, monitor, log, nt_header)

        if self.entry_point_token > 0:
            try:
                if (self.flags & ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) == ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
                    program.get_symbol_table().add_external_entry_point(program.get_image_base() + self.entry_point_token)
                else:
                    cli_stream_metadata = self.metadata.get_metadata_root().get_stream_header(CliStreamMetadata.getName()).get_stream()
                    cli_method_def_row = (cli_stream_metadata.get_table((self.entry_point_token & 0xff000000) >> 24)).get_row(self.entry_point_token & 0x00ffffff)
                    program.get_symbol_table().add_external_entry_point(program.get_image_base() + cli_method_def_row.RVA)

                    self.entry_point_va = program.get_image_base() + cli_method_def_row.RVA
            except Exception as e:
                log.append_exception(e)

    def to_data_type(self):
        struct = StructureDataType("IMAGE_COR20_HEADER", 0)
        struct.add(DWordDataType(), "cb", "Size of the structure")
        struct.add(WordDataType(), "MajorRuntimeVersion", "Version of CLR Runtime")
        struct.add(WordDataType(), "MinorRuntimeVersion", None)
        struct.add(self.metadata.to_data_type(), "MetaData", "RVA and size of MetaData")
        struct.add(ImageCor20Flags(), "Flags", None)
        struct.add(DWordDataType(), "EntryPointToken", "This is a metadata token if not a valid RVA")
        struct.add(self.resources.to_data_type(), "Resources", None)
        struct.add(self.strong_name_signature.to_data_type(), "StrongNameSignature", None)
        struct.add(self.code_manager_table.to_data_type(), "CodeManagerTable", "Should be 0")
        struct.add(self.vtable_fixups.to_data_type(), "VTableFixups", None)
        struct.add(self.export_address_table_jumps.to_data_type(), "ExportAddressTableJumps", "Should be 0")
        struct.add(self.managed_native_header.to_data_type(), "ManagedNativeHeader", "0 unless this is a native image")

        return struct

    def get_cb(self):
        return self.cb

    def get_major_runtime_version(self):
        return self.major_runtime_version

    def get_minor_runtime_version(self):
        return self.minor_runtime_version

    def get_metadata(self):
        return self.metadata

    def get_flags(self):
        return self.flags

    def get_entry_point_token(self):
        return self.entry_point_token

    def get_entry_point_va(self):
        return self.entry_point_va

    def get_resources(self):
        return self.resources

    def get_strong_name_signature(self):
        return self.strong_name_signature

    def get_code_manager_table(self):
        return self.code_manager_table

    def get_vtable_fixups(self):
        return self.vtable_fixups

    def get_export_address_table_jumps(self):
        return self.export_address_table_jumps

    def get_managed_native_header(self):
        return self.managed_native_header


class ImageCor20Flags(EnumDataType):
    PATH = "/PE/CLI/Flags"
    COMIMAGE_FLAGS_ILONLY = 0x00000001
    COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
    COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010
    COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000

    def __init__(self):
        super().__init__(CategoryPath(self.PATH), "COR20_Flags", 4)
        prefix = "COMIMAGE_FLAGS_"
        self.add(prefix + "ILONLY", ImageCor20Flags.COMIMAGE_FLAGS_ILONLY)
        self.add(prefix + "32BITREQUIRED", ImageCor20Flags.COMIMAGE_FLAGS_32BITREQUIRED)
        self.add(prefix + "IL_LIBRARY", ImageCor20Flags.COMIMAGE_FLAGS_IL_LIBRARY)
        self.add(prefix + "STRONGNAMESIGNED", ImageCor20Flags.COMIMAGE_FLAGS_STRONGNAMESIGNED)
        self.add(prefix + "NATIVE_ENTRYPOINT", ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
        self.add(prefix + "TRACKDEBUGDATA", ImageCor20Flags.COMIMAGE_FLAGS_TRACKDEBUGDATA)


class CliMetadataDirectory:
    @staticmethod
    def create_cli_metadata_directory(nt_header, reader):
        # Implementation of this method is not provided in the given Java code.
        pass


class DefaultDataDirectory:
    @staticmethod
    def create_default_data_directory(nt_header, reader):
        # Implementation of this method is not provided in the given Java code.
        pass


class StructureDataType:
    def __init__(self, name, size):
        self.name = name
        self.size = size

    def add(self, data_type, field_name, description=None):
        # Implementation of this method is not provided in the given Java code.
        pass


class DWordDataType:
    def __init__(self):
        super().__init__("DWord", 4)


class WordDataType:
    def __init__(self):
        super().__init__("Word", 2)
```

Please note that I have translated this code into Python, but the actual implementation of certain methods (like `CliMetadataDirectory.create_cli_metadata_directory` and `DefaultDataDirectory.create_default_data_directory`) is not provided in the given Java code. You would need to implement these methods according to your specific requirements.