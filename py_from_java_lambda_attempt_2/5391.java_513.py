Here is the translation of the Java code into Python:

```Python
class IntelHexLoader:
    INTEL_HEX_NAME = "Intel Hex"

    def get_tier(self):
        return "UNTARGETED_LOADER"

    def get_tier_priority(self):
        return 50

    def supports_load_into_program(self):
        return True

    OPTION_NAME_BASE_ADDRESS = "Base Address"
    OPTION_NAME_BLOCK_NAME = "Block Name"
    OPTION_NAME_IS_OVERLAY = "Overlay"

    def find_supported_load_specs(self, provider) -> list:
        load_specs = []
        if MotorolaHexLoader.is_possible_hex_file(provider):
            language_descriptions = get_language_service().get_language_descriptions(False)
            for language_description in language_descriptions:
                compiler_spec_descriptions = language_description.get_compatible_compiler_spec_descriptions()
                for compiler_spec_description in compiler_spec_descriptions:
                    lcs = LanguageCompilerSpecPair(language_description.get_language_id(), compiler_spec_description.get_compiler_spec_id())
                    load_specs.append(LoadSpec(self, 0, lcs, False))
        return load_specs

    def validate_options(self, provider, load_spec, options, program) -> str:
        base_addr = None
        for option in options:
            opt_name = option.name()
            try:
                if opt_name == self.OPTION_NAME_BASE_ADDRESS:
                    base_addr = option.value()
                    if base_addr is None:
                        return "Invalid base address"
                elif opt_name == self.OPTION_NAME_BLOCK_NAME:
                    if not isinstance(option.value(), str):
                        return f"{self.OPTION_NAME_BLOCK_NAME} must be a string"
                elif opt_name == self.OPTION_NAME_IS_OVERLAY:
                    if not isinstance(option.value(), bool):
                        return f"{self.OPTION_NAME_IS_OVERLAY} must be a boolean"
            except ClassCastException as e:
                return f"Invalid type for option: {opt_name} - {e.message}"
        return None

    def get_base_addr(self, options) -> Address:
        base_addr = None
        for option in options:
            opt_name = option.name()
            if opt_name == self.OPTION_NAME_BASE_ADDRESS:
                base_addr = option.value()
        return base_addr

    def get_block_name(self, options) -> str:
        block_name = ""
        for option in options:
            opt_name = option.name()
            if opt_name == self.OPTION_NAME_BLOCK_NAME:
                block_name = option.value()
        return block_name

    def is_overlay(self, options) -> bool:
        is_overlay = False
        for option in options:
            opt_name = option.name()
            if opt_name == self.OPTION_NAME_IS_OVERLAY:
                is_overlay = option.value()
        return is_overlay

    def load_program_into(self, provider, load_spec, options, program, monitor) -> bool:
        base_addr = self.get_base_addr(options)
        if base_addr is None:
            base_addr = program.address_factory.default_address_space.get_address(0)

        try:
            process_intel_hex(provider, options, program, monitor)
            return True
        except AddressOverflowException as e:
            raise IOException(f"Hex file specifies range greater than allowed address space - {e.message}")
        finally:
            if not success:
                prog.release(consumer)
                prog = None

    def process_intel_hex(self, provider, options, program, monitor):
        block_name = self.get_block_name(options)
        is_overlay = self.is_overlay(options)
        base_addr = self.get_base_addr(options)

        if base_addr is None:
            base_addr = program.address_factory.default_address_space.get_address(0)

        if block_name == "" or len(block_name) == 0:
            block_name = generate_block_name(program, is_overlay, base_addr.get_address_space())

        line_num = 0
        mem_image = IntelHexMemImage(program.address_factory.default_address_space, base_addr)
        try (reader in BufferedReader(InputStreamReader(provider.get_input_stream(0)))):
            while (line := reader.readline()) is not None:
                monitor.check_cancelled()

                line_num += 1
                if line_num % 1000 == 1:
                    monitor.set_message(f"Reading in ... {line_num}")

                msg = mem_image.parse_line(line)
                if msg is not None:
                    log.append_msg(f"Line: {line_num} - {msg}")
        finally:
            success = True
            try:
                final_symbol_table = program.symbol_table
                final_address_space = program.address_factory.default_address_space
                start_eip, start_cs, start_ip = mem_image.get_start_eip(), mem_image.get_start_cs(), mem_image.get_start_ip()
                entry_addr = None
                if start_eip != -1:
                    entry_addr = address_space.get_address(start_eip)
                elif start_cs != -1 and start_ip != -1:
                    if isinstance(address_space, SegmentedAddressSpace):
                        seg_space = (SegmentedAddressSpace) address_space
                        entry_addr = seg_space.get_address(start_cs, start_ip)

                if entry_addr is not None:
                    create_symbol(symbol_table, entry_addr, "entry", True, namespace)
            except Exception as e:
                log.append_msg(f"Could not create symbol at entry point: {e}")

    def get_name(self):
        return self.INTEL_HEX_NAME

class LoadSpec:
    def __init__(self, loader, offset, pair, is_entry):
        self.loader = loader
        self.offset = offset
        self.pair = pair
        self.is_entry = is_entry

class LanguageCompilerSpecPair:
    def __init__(self, language_id, compiler_spec_id):
        self.language_id = language_id
        self.compiler_spec_id = compiler_spec_id

class IntelHexMemImage:
    def __init__(self, address_space, base_addr):
        self.address_space = address_space
        self.base_addr = base_addr

    def parse_line(self, line) -> str:
        # implementation of parsing intel hex file lines
        pass

    def create_memory(self, name, provider_name, block_name, is_overlay, program, monitor) -> str:
        # implementation of creating memory from intel hex file
        pass

class SymbolTable:
    def add_external_entry_point(self, addr):
        # implementation of adding external entry point to symbol table
        pass

    def create_label(self, addr, name, namespace, source_type):
        # implementation of creating label in symbol table
        pass

def generate_block_name(program, is_overlay, address_space) -> str:
    # implementation of generating block name from program and overlay status
    pass

class MotorolaHexLoader:
    @staticmethod
    def is_possible_hex_file(provider) -> bool:
        # implementation of checking if provider contains possible intel hex file
        pass

def get_language_service() -> object:
    # implementation of getting language service
    pass

# usage example:

intel_loader = IntelHexLoader()
load_spec = LoadSpec(intel_loader, 0, LanguageCompilerSpecPair("language_id", "compiler_spec_id"), False)
options = [Option(OPTION_NAME_BASE_ADDRESS, Address(0))]
program = Program(address_factory=AddressFactory())
monitor = TaskMonitor()

try:
    intel_loader.load_program_into(provider, load_spec, options, program, monitor)
except IOException as e:
    print(f"Error: {e.message}")
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.