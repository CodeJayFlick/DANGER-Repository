class Language:
    def __init__(self):
        pass  # Initialize with default values if needed

    def get_language_id(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_language_description(self) -> dict:  # Assuming it's a dictionary
        raise NotImplementedError("Subclasses must implement this method")

    def get_parallel_instruction_helper(self) -> object or None:
        return None

    def get_processor(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_version(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_minor_version(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_address_factory(self) -> object:  # Assuming it's an AddressFactory
        return None

    def get_default_space(self) -> object or None:  # Assuming it's an AddressSpace
        return None

    def get_default_data_space(self) -> object or None:
        return None

    def is_big_endian(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_instruction_alignment(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def supports_pcode(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def is_volatile(self, addr: object or None) -> bool:
        return False

    def parse(self, buf: bytes, context: dict, in_delay_slot: bool) -> tuple or None:
        # Assuming it returns a tuple of InstructionPrototype
        raise NotImplementedError("Subclasses must implement this method")

    def get_number_of_user_defined_op_names(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_user_defined_op_name(self, index: int) -> str or None:
        return None

    def get_registers(self) -> list:
        # Assuming it returns a list of Register
        return []

    def get_register_names(self) -> list:
        # Assuming it returns a list of strings (register names)
        return []

    def get_program_counter(self) -> object:  # Assuming it's a Register
        raise NotImplementedError("Subclasses must implement this method")

    def get_context_base_register(self) -> object or None:  # Assuming it's a Register
        return None

    def get_default_memory_blocks(self) -> list:
        # Assuming it returns a list of MemoryBlockDefinition
        return []

    def get_default_symbols(self) -> list:
        # Assuming it returns a list of AddressLabelInfo
        return []

    def apply_context_settings(self, ctx: dict):
        pass  # No-op

    def reload_language(self, task_monitor: object or None) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_compatible_compiler_spec_descriptions(self) -> list:
        # Assuming it returns a list of CompilerSpecDescription
        return []

    def get_compiler_spec_by_id(self, compiler_spec_id: str) -> tuple or None:
        # Assuming it returns a tuple (CompilerSpec, Exception)
        raise NotImplementedError("Subclasses must implement this method")

    def get_default_compiler_spec(self) -> object:  # Assuming it's a CompilerSpec
        return None

    def has_property(self, key: str) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_property_as_int(self, key: str, default_int: int) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_property_as_boolean(self, key: str, default_bool: bool) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_property(self, key: str) -> str or None:
        return None

    def has_manual(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def get_manual_entry(self, instruction_mnemonic: str) -> tuple or None:
        # Assuming it returns a tuple (ManualEntry, Exception)
        raise NotImplementedError("Subclasses must implement this method")

    def get_sorted_vector_registers(self) -> list:
        # Assuming it returns a list of Register
        return []
