Here is the translation of the Java interface `ElfLoadHelper` into a Python class:

```Python
class ElfLoadHelper:
    def __init__(self):
        pass  # Initialize with default values if needed

    def get_program(self) -> object:  # Program
        """Get program object"""
        return None  # Replace with actual implementation

    def get_elf_header(self) -> object:  # ElfHeader
        """Get ELF Header object"""
        return None  # Replace with actual implementation

    def get_log(self) -> object:  # MessageLog
        """Get the message log"""
        return None  # Replace with actual implementation

    def log(self, msg: str):  # void
        """Output loader log message"""
        print(msg)

    def log(self, t: Exception):  # void
        """Output loader log message. The analyzers will pick this up and disassemble the code."""
        raise t

    def mark_as_code(self, address: object):  # void
        """Mark this location as code in the CodeMap"""
        pass  # Replace with actual implementation

    def create_one_byte_function(self, name: str, address: object, is_entry: bool) -> object:  # Function
        """Create a one-byte function, so that when the code is analyzed, it will be disassembled, and the function created with the correct body"""
        return None  # Replace with actual implementation

    def create_external_function_linkage(self, name: str, function_addr: object, indirect_pointer_addr: object) -> object:
        """Create an external function within the UNKNOWN space and a corresponding thunk at the internalFunctionAddr. """
        return None  # Replace with actual implementation

    def create_undefined_data(self, address: object, length: int) -> object:  # Data
        """Create an undefined data item to reserve the location as data"""
        return None  # Replace with actual implementation

    def create_data(self, address: object, dt: object) -> object:
        """Create a data item using the specified data type"""
        return None  # Replace with actual implementation

    def set_elf_symbol_address(self, elf_symbol: object, address: object):  # void
        """Add specified elfSymbol to the loader symbol map after its program address has been assigned"""
        pass  # Replace with actual implementation

    def get_elf_symbol_address(self, elf_symbol: object) -> object:
        """Get the memory address of a previously resolved symbol"""
        return None  # Replace with actual implementation

    def create_symbol(self, addr: object, name: str, is_primary: bool, pin_absolute: bool, namespace: object) -> object:
        """Create the specified label symbol within the program"""
        return None  # Replace with actual implementation

    def find_load_address(self, section: object, byte_offset_within_section: int) -> object:
        """Find the program address at which a specified offset within a section or segment was loaded/resolved"""
        return None  # Replace with actual implementation

    def get_default_address(self, addressable_word_offset: int) -> object:
        """Get the program address for an addressableWordOffset within the default address space"""
        return None  # Replace with actual implementation

    def get_image_base_word_adjustment_offset(self) -> int:
        """Get the program image base offset adjustment"""
        return 0  # Default value, replace with actual implementation if needed

    def get_got_value(self) -> object:
        """Returns the appropriate .got (Global Offset Table) section address using the DT_PLTGOT value defined in the .dynamic section"""
        return None  # Replace with actual implementation

    def allocate_linkage_block(self, alignment: int, size: int, purpose: str) -> object:
        """Get a free aligned address range within the program's memory block structure to facilitate dynamic memory block allocation requirements"""
        return None  # Replace with actual implementation

    def get_original_value(self, addr: object, sign_extend: bool) -> int:
        """Get the original memory value at the specified address if a relocation was applied at the specified address (not containing). """
        raise MemoryAccessException("Memory read failed")  # Default exception handling
```

Please note that this is just an approximation of how you could translate Java code into Python.