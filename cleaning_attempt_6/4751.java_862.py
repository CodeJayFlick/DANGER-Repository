class AbstractClassicProcessor:
    def __init__(self, header: 'MachHeader', program):
        self.header = header
        self.program = program

    def perform(self, segment_name: str, section_name: str, address_value: int,
                 from_dylib: str, n_list: object, is_weak: bool, monitor) -> None:
        # Removed Java code specific to SystemUtilities and Apache License.
        
        language = self.program.get_language()
        memory = self.program.get_memory()
        listing = self.program.get_listing()

        if symbol := self.get_symbol(n_list):
            listing.set_comment(symbol.address, CodeUnit.PlateComment, from_dylib)
            
            offset = symbol.address.offset
            original_bytes = None
            
            file_type = self.header.file_type
            
            if file_type in [MachHeaderFileTypes.MH_EXECUTE,
                             MachHeaderFileTypes.MH_DYLIB,
                             MachHeaderFileTypes.MH_BUNDLE,
                             MachHeaderFileTypes.MH_DYLINKER]:
                bytes = converter.get_bytes(offset)
                
                original_bytes = bytearray(bytes)
                memory.get_bytes(address, original_bytes)
                memory.set_bytes(address, bytes)
            elif file_type == MachHeaderFileTypes.MH_KEXT_BUNDLE:
                if self.header.cpu_type in [CpuTypes.CPU_TYPE_X86,
                                             CpuTypes.CPU_TYPE_X86_64]:
                    block = memory.get_block(address)
                    
                    if block.is_execute():
                        instruction_byte = memory.get_byte(address - 1)
                        
                        if instruction_byte == 0xe8 or instruction_byte == 0xe9:
                            difference = offset - address_value - 4
                            
                            bytes = converter.get_bytes(difference)
                            original_bytes = bytearray(bytes)
                            memory.get_bytes(address, original_bytes)
                            memory.set_bytes(address, bytes)
                elif self.header.cpu_type == CpuTypes.CPU_TYPE_ARM:  # TODO ios arm kext files
                    pass
            else:
                bytes = converter.get_bytes(offset)
                
                original_bytes = bytearray(bytes)
                memory.get_bytes(address, original_bytes)
                memory.set_bytes(address, bytes)

        if not handled:
            self.program.get_relocation_table().add(address, file_type,
                                                      [0], original_bytes, symbol.name)
            
            if not handled:
                self.program.get_bookmark_manager().set_bookmark(
                    address, BookmarkType.ERROR,
                    "Unhandled Classic Binding",
                    f"Unable to fixup classic binding. This instruction will contain an invalid destination / fixup."
                )

    def get_symbol(self, n_list):
        symbol_table = self.program.get_symbol_table()
        
        for symbol in symbol_table:
            if symbol.name == n_list.string():
                return symbol
        return None

    def get_section_name(self, address: int) -> object:
        sections = self.header.all_sections
        
        for section in sections:
            if section.address <= address and address < section.address + section.size:
                return section
        return None  # TODO handle this case better

    def get_classic_ordinal_name(self, library_ordinal: int):
        switch_dict = {
            NListConstants.SELF_LIBRARY_ORDINAL: "this-image",
            NListConstants.EXECUTABLE_ORDINAL: "main-executable",
            NListConstants.DYNAMIC_LOOKUP_ORDINAL: "flat-namespace"
        }
        
        if library_ordinal in switch_dict:
            return switch_dict[library_ordinal]
        
        dylib_commands = self.header.load_commands(DynamicLibraryCommand)
        
        if library_ordinal >= len(dylib_commands):
            return f"dyld info library ordinal out of range {library_ordinal}"
        
        dylib_command = dylib_commands[library_ordinal]
        dynamic_library = dylib_command.get_dynamic_library()
        load_command_string_name = dynamic_library.name
        
        return load_command_string_name

    def get_relocation_base(self):
        segments = self.header.load_commands(SegmentCommand)
        
        if self.program.default_pointer_size == 8:
            for segment in segments:
                if segment.is_write():
                    return segment.vm_address
        else:
            first_segment = segments[0]
            
            return first_segment.vm_address

class MachHeader:
    def __init__(self):
        pass

    @property
    def file_type(self) -> int:
        # TODO implement this property
        pass

    @property
    def cpu_type(self) -> int:
        # TODO implement this property
        pass

    @property
    def flags(self) -> int:
        # TODO implement this property
        pass

class SegmentCommand:
    def __init__(self):
        pass

    @property
    def is_write(self) -> bool:
        # TODO implement this property
        pass

    @property
    def vm_address(self) -> int:
        # TODO implement this property
        pass

class DynamicLibraryCommand:
    def __init__(self):
        pass

    @property
    def get_dynamic_library(self) -> object:
        # TODO implement this method
        pass

    @property
    def name(self) -> str:
        # TODO implement this property
        pass

# Removed Java code specific to SystemUtilities and Apache License.
