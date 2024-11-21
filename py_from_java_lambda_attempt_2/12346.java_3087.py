Here is the translation of the Java code into Python:

```Python
class MenuResourceDataType:
    MF_POPUP = 0x0010
    MF_END = 0x0080
    LAST = 0x0090

    def __init__(self):
        self.this(null, "MenuResource", null)

    @staticmethod
    def put(class_name: str) -> None:
        ClassTranslator.put("ghidra.app.plugin.prototype.data.MenuResourceDataType",
                             MenuResourceDataType.__name__)

    def get_description(self) -> str:
        return "Menu stored as a Resource"

    def get_mnemonic(self, settings: Settings) -> str:
        return "MenuRes"

    @staticmethod
    def add_menu_item_template_header_structure(mem_buffer: MemBuffer,
                                                 comps: List[DataTypeComponent],
                                                 temp_offset: int) -> int:
        version_number = mem_buffer.get_short(temp_offset)
        if version_number != 0x0000:
            Msg.error(self, "Invalid MENUITEM_TEMPLATE_HEADER version number")
            return -1
        menu_items_offset = mem_buffer.get_short(temp_offset + 2)
        if menu_items_offset < 0:
            Msg.debug(self, "Invalid MENUITEM_TEMPLATE_HEADER offset")
            return -1

        temp_offset += add_comp(menu_item_template_header_structure(), 4,
                                 "Menu Item Template Header Structure",
                                 mem_buffer.get_address(),
                                 comps, temp_offset)

        return temp_offset

    @staticmethod
    def menu_item_template_header_structure() -> StructureDataType:
        struct = StructureDataType("MENUITEM_TEMPLATE_HEADER", 0)
        struct.add(WordDataType.data_type)
        struct.add(WordDataType.data_type)

        try:
            struct.get_component(0).set_field_name("versionNumber")
            struct.get_component(1).set_field_name("offset")

        except DuplicateNameException as e:
            Msg.debug(self, "Unexpected exception building MENUITEM_TEMPLATE_HEADER", e)

        struct.get_component(0).set_comment("Version number of menu")
        struct.get_component(1).set_comment("Menu items offset.")

        return struct

    @staticmethod
    def add_menu_item_template(mem_buffer: MemBuffer,
                                comps: List[DataTypeComponent],
                                temp_offset: int,
                                mt_option: short) -> int:
        if mt_option == MF_POPUP:
            temp_offset += add_comp(WordDataType.data_type, 2, "mtOption",
                                     mem_buffer.get_address(), comps, temp_offset)
        else:
            temp_offset += add_comp(WordDataType.data_type, 2, "mtOption",
                                     mem_buffer.get_address(), comps, temp_offset)

            temp_offset += add_comp(WordDataType.data_type, 2, "mtID",
                                     mem_buffer.get_address().add(temp_offset), comps,
                                     temp_offset)
        return temp_offset

    @staticmethod
    def find_unicode_length(byte_array: bytearray) -> int:
        i = 0
        while i <= len(byte_array):
            if byte_array[i] == 0 and byte_array[i + 1] == 0:
                return (i + 2)
            i += 2

        return -1

    def get_representation(self, buf: MemBuffer, settings: Settings, length: int) -> str:
        return "<Menu-Resource>"

    @staticmethod
    def add_comp(data_type: DataType,
                 len: int,
                 field_name: str,
                 address: Address,
                 comps: List[DataTypeComponent],
                 current_offset: int) -> int:
        if len > 0:
            readOnlyDataTypeComponent = ReadOnlyDataTypeComponent(
                data_type, self, len, len(comps), current_offset, field_name, None
            )
            comps.append(readOnlyDataTypeComponent)
            return current_offset + len

    @staticmethod
    def add_unicode_string(mem_buffer: MemBuffer,
                            comps: List[DataTypeComponent],
                            temp_offset: int) -> str:
        byte_array = bytearray(1024)
        mem_buffer.get_bytes(byte_array, temp_offset)

        if find_unicode_length(byte_array) >= 2:
            return "<Menu-Resource>"

    @staticmethod
    def clone(dtm: DataTypeManager) -> MenuResourceDataType:
        if dtm == get_data_type_manager():
            return self

        return new_menu_resource_data_type(dtm)
```

Please note that Python does not support direct translation of Java code. It requires manual conversion and might have some differences in syntax, semantics or functionality compared to the original Java code.