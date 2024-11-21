Here is the translation of the Java code into Python:

```Python
class BinaryLoader:
    BINARY_NAME = "Raw Binary"
    OPTION_NAME_LEN = "Length"
    OPTION_NAME_FILE_OFFSET = "File Offset"
    OPTION_NAME_BASE_ADDR = "Base Address"
    OPTION_NAME_BLOCK_NAME = "Block Name"
    OPTION_NAME_IS_OVERLAY = "Overlay"

    def __init__(self):
        pass

    @staticmethod
    def get_tier():
        return "UNTARGETED_LOADER"

    @staticmethod
    def get_tier_priority():
        return 100

    @staticmethod
    def supports_load_into_program():
        return True

    @staticmethod
    def find_supported_load_specs(provider):
        load_specs = []
        language_descriptions = get_language_service().get_language_descriptions(False)
        for language_description in language_descriptions:
            compiler_spec_descriptions = language_description.get_compatible_compiler_spec_descriptions()
            for compiler_spec_description in compiler_spec_descriptions:
                lcs = LanguageCompilerSpecPair(language_description.get_language_id(), compiler_spec_description.get_compiler_spec_id())
                load_specs.append(LoadSpec(self, 0, lcs, False))
        return load_specs

    @staticmethod
    def parse_long(option):
        value = option.get_value()
        if value is None:
            return None
        rendered = str(value)
        if rendered.lower().startswith("0x"):
            rendered = rendered[2:]
        return NumericUtilities.parse_hex_long(rendered)

    @staticmethod
    def validate_options(provider, load_spec, options, program):
        base_addr = None
        length = 0
        file_offset = 0
        orig_file_length = provider.length()
        is_overlay = False
        try:
            for option in options:
                if option.get_name() == OPTION_NAME_BASE_ADDR:
                    base_addr = Address(option.get_value())
                elif option.get_name() == OPTION_NAME_FILE_OFFSET:
                    file_offset = BinaryLoader.parse_long(option)
                elif option.get_name() == OPTION_NAME_LEN:
                    length = BinaryLoader.parse_long(option)
        except Exception as e:
            return str(e)

        if base_addr is None:
            return "Invalid base address"
        for option in options:
            if option.get_name() == OPTION_NAME_FILE_OFFSET and file_offset < 0 or file_offset >= orig_file_length:
                return f"File Offset must be greater than 0 and less than file length {orig_file_length} (0x{Long.toHexString(orig_file_length)})"
            elif option.get_name() == OPTION_NAME_LEN and length < 0 or length > orig_file_length:
                return f"Length must be greater than 0 and less than or equal to file length {orig_file_length} (0x{Long.toHexString(orig_file_length)})"

        if file_offset + length > orig_file_length:
            return f"File Offset + Length (0x{file_offset + length}) too large; set length to 0x{Long.toHexString(orig_file_length - file_offset)}"
        if file_offset == -1 or length == -1:
            return "Invalid file offset specified"

        if program is not None and program.get_memory().intersects(base_addr, base_addr.add(length - 1)) and not is_overlay:
            return f"Memory Conflict: Use <Options...> to change the base address!"

        return super.validate_options(provider, load_spec, options, program)

    @staticmethod
    def get_base_addr(options):
        if options is None or len(options) == 0:
            return None

        for option in options:
            if option.get_name() == BinaryLoader.OPTION_NAME_BASE_ADDR:
                return Address(option.get_value())

        return None

    @staticmethod
    def get_length(options):
        length = 0
        if options is not None and len(options) > 0:
            for option in options:
                if option.get_name() == BinaryLoader.OPTION_NAME_LEN:
                    length = BinaryLoader.parse_long(option)

        return length

    @staticmethod
    def get_file_offset(options):
        file_offset = 0
        if options is not None and len(options) > 0:
            for option in options:
                if option.get_name() == BinaryLoader.OPTION_NAME_FILE_OFFSET:
                    file_offset = BinaryLoader.parse_long(option)

        return file_offset

    @staticmethod
    def get_block_name(options):
        block_name = ""
        if options is not None and len(options) > 0:
            for option in options:
                if option.get_name() == BinaryLoader.OPTION_NAME_BLOCK_NAME:
                    block_name = str(option.get_value())

        return block_name

    @staticmethod
    def get_is_overlay(options):
        is_overlay = False
        if options is not None and len(options) > 0:
            for option in options:
                if option.get_name() == BinaryLoader.OPTION_NAME_IS_OVERLAY:
                    is_overlay = bool(option.get_value())

        return is_overlay

    @staticmethod
    def load_program(provider, program_name, program_folder, load_spec, options, log):
        pair = load_spec.get_language_compiler_spec()
        language = get_language_service().get_language(pair.language_id)
        compiler_spec = language.get_compiler_spec_by_id(pair.compiler_spec_id)

        base_addr = Address(0)
        prog = create_program(provider, program_name, base_addr, BinaryLoader.BINARY_NAME, language, compiler_spec, None)
        success = False
        try:
            success = load_into(provider, load_spec, options, log, prog, None)
            if success:
                create_default_memory_blocks(prog, language, log)

        finally:
            if not success:
                prog.release(None)
                prog = None

        results = []
        if prog is not None:
            results.append(prog)

        return results

    @staticmethod
    def load_program_into(provider, load_spec, options, log):
        length = BinaryLoader.get_length(options)
        file_offset = BinaryLoader.get_file_offset(options)
        base_addr = BinaryLoader.get_base_addr(options)
        block_name = BinaryLoader.get_block_name(options)
        is_overlay = BinaryLoader.get_is_overlay(options)

        if length == 0:
            length = provider.length()

        length = clip_to_memory_space(length, log, None)

        file_bytes = MemoryBlockUtils.create_file_bytes(None, provider, file_offset, length, None)
        try:
            space = prog.get_address_factory().get_default_address_space()
            if base_addr is None:
                base_addr = space.get_address(0)
            create_block(prog, is_overlay, block_name, base_addr, file_bytes, length, log)

            return True

        except AddressOverflowException as e:
            raise Exception("Invalid address range specified: start:" + str(base_addr) + ", length:" + str(length) + " - end address exceeds address space boundary!")

    @staticmethod
    def create_block(prog, is_overlay, block_name, base_addr, file_bytes, length, log):
        if prog.get_memory().intersects(base_addr, base_addr.add(length - 1)) and not is_overlay:
            raise Exception("Can't load " + str(length) + " bytes at address " + str(base_addr) + " since it conflicts with existing memory blocks!")

        MemoryBlockUtils.create_initialized_block(prog, is_overlay, block_name, base_addr, file_bytes, 0, length, None, "Binary Loader", True, not is_overlay, not is_overlay, log)

    @staticmethod
    def clip_to_memory_space(length, log, prog):
        space = prog.get_address_factory().get_default_address_space()
        max_length = space.get_max_address().get_offset() + 1
        if max_length > 0 and length > max_length:
            log.append_msg("Clipped file to fit into memory space")
            length = max_length

        return length

    @staticmethod
    def get_default_options(provider, load_spec, domain_object, load_into_program):
        orig_file_length = provider.length()
        try:
            for option in options:
                if option.get_name() == BinaryLoader.OPTION_NAME_BASE_ADDR:
                    base_addr = Address(option.get_value())
                elif option.get_name() == BinaryLoader.OPTION_NAME_FILE_OFFSET:
                    file_offset = BinaryLoader.parse_long(option)
                elif option.get_name() == BinaryLoader.OPTION_NAME_LEN:
                    length = BinaryLoader.parse_long(option)

        except Exception as e:
            return str(e)

        if base_addr is None or length < 0 or length > orig_file_length:
            return "Invalid file offset specified"

        list = []
        if load_into_program:
            list.append(new Option(BinaryLoader.OPTION_NAME_IS_OVERLAY, is_overlay))
        else:
            is_overlay = False

        list.append(new Option(BinaryLoader.OPTION_NAME_BLOCK_NAME, block_name, String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-blockName"))
        list.append(new Option(BinaryLoader.OPTION_NAME_BASE_ADDR, base_addr, Address.class, Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"))
        list.append(new Option(BinaryLoader.OPTION_NAME_FILE_OFFSET, new HexLong(file_offset), HexLong.class, Loader.COMMAND_LINE_ARG_PREFIX + "-fileOffset"))
        list.append(new Option(BinaryLoader.OPTION_NAME_LEN, new HexLong(length), HexLong.class, Loader.COMMAND_LINE_ARG_PREFIX + "-length"))

        return super.get_default_options(provider, load_spec, domain_object, load_into_program)

    @staticmethod
    def get_name():
        return BinaryLoader.BINARY_NAME

    @staticmethod
    def should_apply_processor_labels_by_default():
        return True