Here is the translation of the Java code into Python:

```Python
class DebugDataDirectory:
    NAME = "IMAGE_DIRECTORY_ENTRY_DEBUG"

    def __init__(self):
        pass

    @staticmethod
    def create_debug_data_directory(nt_header, reader) -> 'DebugDataDirectory':
        debug_data_directory = reader.get_factory().create(DebugDataDirectory)
        debug_data_directory.init_debug_data_directory(nt_header, reader)
        return debug_data_directory

    def init_debug_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

    @property
    def get_directory_name(self) -> str:
        return self.NAME

    def parse(self) -> bool:
        ptr = self.get_pointer()
        if ptr < 0:
            return False
        
        parser = DebugDirectoryParser.create_debug_directory_parser(reader=reader, pointer=ptr, size=self.size, nt_header=nt_header)
        return True

    @property
    def get_parser(self):
        return self.parser

    def markup(self, program: 'Program', is_binary: bool, monitor: TaskMonitor, log: MessageLog, nt_header: NTHeader) -> None:
        if not program.get_memory().contains(self.virtual_address):
            return
        
        create_directory_bookmark(program=program, address=self.virtual_address)
        
        space = program.get_address_factory().get_default_address_space()
        
        dd_arr = self.parser.get_debug_directories()
        for dd in dd_arr:
            PeUtils.create_data(program=program, addr=self.virtual_address, data_type=dd.to_data_type(), log=log)
            self.virtual_address += DebugDirectory.IMAGE_SIZEOF_DEBUG_DIRECTORY
            
            if (data_addr := self.get_data_address(dd=dd, is_binary=is_binary, space=space, nt_header=nt_header)) is not None:
                success = create_fragment(program=program, name="Debug Data", start=data_addr, end=data_addr + dd.size_of_data())
                if not success:
                    log.append_msg("Unable to create fragment: Debug Data")
        
        self.markup_debug_code_view(program=program, is_binary=is_binary, log=log, space=space)
        self.markup_debig_misc(program=program, is_binary=is_binary, log=log, space=space)

    def markup_debug_code_view(self, program: 'Program', is_binary: bool, log: MessageLog, space: AddressSpace) -> None:
        dcv = self.parser.get_debug_code_view()
        
        if (pdb_info := dcv.get_pdb_info()) is not None:
            set_plate_comment(program=program, addr=self.virtual_address, comment="CodeView PDB Info")
            PeUtils.create_data(program=program, addr=self.virtual_address, data_type=pdb_info.to_data_type(), log=log)
        
        if (dot_net_pdb_info := dcv.get_dot_net_pdb_info()) is not None:
            set_plate_comment(program=program, addr=self.virtual_address, comment=".NET PDB Info")
            PeUtils.create_data(program=program, addr=self.virtual_address, data_type=dot_net_pdb_info.to_data_type(), log=log)

    def markup_debig_misc(self, program: 'Program', is_binary: bool, log: MessageLog, space: AddressSpace) -> None:
        dm = self.parser.get_debug_misc()
        
        if (data_addr := self.get_data_address(dd=dm.get_debug_directory(), is_binary=is_binary, space=space, nt_header=nt_header)) is not None:
            set_plate_comment(program=program, addr=self.virtual_address, comment="Misc Debug Info")
            PeUtils.create_data(program=program, addr=self.virtual_address, data_type=dm.to_data_type(), log=log)

    def get_data_address(self, dd: 'DebugDirectory', is_binary: bool, space: AddressSpace, nt_header: NTHeader) -> Address:
        ptr = 0
        if is_binary:
            ptr = dd.get_pointer_to_raw_data()
            if ptr != 0 and not nt_header.check_pointer(ptr):
                Msg.error(self, f"Invalid pointer {ptr}")
                return None
        
        elif not is_binary:
            ptr = dd.get_address_of_raw_data()

        if ptr != 0:
            if is_binary:
                return space.get_address(ptr)
            else:
                return space.get_address(ptr + nt_header.get_optional_header().get_image_base())
        
        return None

    def to_data_type(self) -> 'DataType':
        struct = StructureDataType(NAME, 0)
        dd_arr = self.parser.get_debug_directories()
        for sc in dd_arr:
            struct.add(sc.to_data_type(), sc.description, None)

        struct.set_category_path(CategoryPath("/PE"))
        return struct

    def write_bytes(self, raf: 'RandomAccessFile', dc: DataConverter, template: PortableExecutable) -> None:
        optional_header = template.get_nt_header().get_optional_header()
        original_data_dirs = optional_header.get_data_directories()

        if optional_header.get_number_of_rva_and_sizes() <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG:
            return
        
        if (original_data_dir := original_data_dirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG]) is None or original_data_dir.size == 0:
            return
        
        template_ddd = DebugDataDirectory(template=template, nt_header=nt_header)
        
        dd_arr = self.parser.get_debug_directories()
        for i in range(len(dd_arr)):
            if (dd := dd_arr[i]).size_of_data() == 0 or dd.pointer_to_raw_data() == 0:
                continue
            
            ptr = dd.get_pointer_to_raw_data()
            if not nt_header.check_pointer(ptr):
                Msg.error(self, f"Invalid pointer {ptr}")
                continue
            
            raf.seek(ptr)
            raf.write(template_ddd.to_bytes(dc))

    def update_pointers(self, offset: int, post_offset: int) -> None:
        debug_dirs = self.parser.get_debug_directories()
        
        for dd in debug_dirs:
            if (size := dd.size_of_data()) == 0 or (ptr := dd.pointer_to_raw_data()) == 0:
                continue
            
            dd.update_pointers(offset=offset, post_offset=post_offset)
```

Please note that Python does not support static methods and properties like Java. Also, the `@staticmethod` decorator is used in Java to define a method that can be called without creating an instance of its class. In Python, you would typically use a regular function or a classmethod for this purpose.

Additionally, Python's type system is dynamically typed, which means it does not require explicit type definitions like Java. However, some IDEs and linters may suggest adding type hints to improve code readability and maintainability.