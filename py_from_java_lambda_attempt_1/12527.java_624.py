Here is the translation of the Java interface `CodeUnit` into a Python class:

```Python
class CodeUnit:
    MNEMONIC = -1
    NO_COMMENT = -1
    EOL_COMMENT = 0
    PRE_COMMENT = 1
    POST_ COMMENT = 2
    PLATE_COMMENT = 3
    REPEATABLE_COMMENT = 4

    def __init__(self):
        pass

    def get_address_string(self, show_block_name: bool, pad: bool) -> str:
        raise NotImplementedError("Method not implemented")

    def set_property(self, name: str, value: Saveable) -> None:
        raise NotImplementedError("Method not implemented")

    def set_property(self, name: str, value: str) -> None:
        raise NotImplementedError("Method not implemented")

    def set_property(self, name: str, value: int) -> None:
        raise NotImplementedError("Method not implemented")

    def set_property(self, name: str) -> None:
        raise NotImplementedError("Method not implemented")

    def get_object_property(self, name: str) -> Saveable:
        raise NotImplementedError("Method not implemented")

    def get_string_property(self, name: str) -> str:
        raise NotImplementedError("Method not implemented")

    def get_int_property(self, name: str) -> int:
        raise NotImplementedError("Method not implemented")

    def has_property(self, name: str) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_void_property(self, name: str) -> bool:
        raise NotImplementedError("Method not implemented")

    def property_names(self) -> Iterator[str]:
        raise NotImplementedError("Method not implemented")

    def remove_property(self, name: str) -> None:
        raise NotImplementedError("Method not implemented")

    def visit_property(self, visitor: PropertyVisitor, propertyName: str) -> None:
        raise NotImplementedError("Method not implemented")

    def get_label(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_symbols(self) -> Symbol[]:  # Python list
        raise NotImplementedError("Method not implemented")

    def get_primary_symbol(self) -> Symbol:
        raise NotImplementedError("Method not implemented")

    def get_min_address(self) -> Address:
        raise NotImplementedError("Method not implemented")

    def get_max_address(self) -> Address:
        raise NotImplementedError("Method not implemented")

    def get_mnemonic_string(self) -> str:
        raise NotImplementedError("Method not implemented")

    def get_comment(self, comment_type: int) -> str:
        raise NotImplementedError("Method not implemented")

    def get_comment_as_array(self, comment_type: int) -> List[str]:
        raise NotImplementedError("Method not implemented")

    def set_comment(self, comment_type: int, comment: str) -> None:
        raise NotImplementedError("Method not implemented")

    def set_comment_as_array(self, comment_type: int, comment: List[str]) -> None:
        raise NotImplementedError("Method not implemented")

    def is_successor(self, code_unit: 'CodeUnit') -> bool:
        raise NotImplementedError("Method not implemented")

    def get_length(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_bytes(self) -> bytes:
        raise NotImplementedError("Method not implemented")

    def get_bytes_in_code_unit(self, buffer: bytearray, offset: int) -> None:
        raise NotImplementedError("Method not implemented")

    def contains(self, test_addr: Address) -> bool:
        raise NotImplementedError("Method not implemented")

    def compare_to(self, addr: Address) -> int:
        raise NotImplementedError("Method not implemented")

    def add_mnemonic_reference(self, ref_addr: Address, ref_type: RefType, source_type: SourceType) -> None:
        raise NotImplementedError("Method not implemented")

    def remove_mnemonic_reference(self, ref_addr: Address) -> None:
        raise NotImplementedError("Method not implemented")

    def get_mnemonic_references(self) -> List[Reference]:
        raise NotImplementedError("Method not implemented")

    def add_operand_reference(self, index: int, ref_addr: Address, ref_type: RefType, source_type: SourceType) -> None:
        raise NotImplementedError("Method not implemented")

    def remove_operand_reference(self, index: int, ref_addr: Address) -> None:
        raise NotImplementedError("Method not implemented")

    def get_references_from(self) -> List[Reference]:
        raise NotImplementedError("Method not implemented")

    def get_reference_iterator_to(self) -> ReferenceIterator:
        raise NotImplementedError("Method not implemented")

    def get_program(self) -> Program:
        raise NotImplementedError("Method not implemented")

    def get_external_reference(self, op_index: int) -> ExternalReference:
        raise NotImplementedError("Method not implemented")

    def remove_external_reference(self, op_index: int) -> None:
        raise NotImplementedError("Method not implemented")

    def set_primary_memory_reference(self, ref: Reference) -> None:
        raise NotImplementedError("Method not implemented")

    def set_stack_reference(self, op_index: int, offset: int, source_type: SourceType, ref_type: RefType) -> None:
        raise NotImplementedError("Method not implemented")

    def set_register_reference(self, op_index: int, reg: Register, source_type: SourceType, ref_type: RefType) -> None:
        raise NotImplementedError("Method not implemented")

    def get_num_operands(self) -> int:
        raise NotImplementedError("Method not implemented")

    def get_address(self, op_index: int) -> Address:
        raise NotImplementedError("Method not implemented")

    def get_scalar(self, op_index: int) -> Scalar:
        raise NotImplementedError("Method not implemented")
```

Please note that this is a direct translation of the Java interface into Python. You may need to adjust it according to your specific requirements and constraints.