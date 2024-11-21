class SectionAttributes:
    SECTION_ATTRIBUTES_MASK = 0xffffff00
    SECTION_ATTRIBUTES_USR = 0xff000000
    SECTION_ATTRIBUTES_SYS = 0x00ffff00

    S_ATTR_PURE_INSTRUCTIONS = 0x80000000
    S_ATTR_NO_TOC = 0x40000000
    S_ATTR_STRIP_STATIC_SYMS = 0x20000000
    S_ATTR_NO_DEAD_STRIp = 0x10000000
    S_ATTR_LIVE_SUPPORT = 0x08000000
    S_ATTR_SELF_MODIFYING_CODE = 0x04000000
    S_ATTR_SOME_INSTRUCTIONS = 0x00000400
    S_ATTR_EXT_RELOC = 0x00000200
    S_ATTR_LOC_RELOC = 0x00000100

    @staticmethod
    def get_attribute_names(attributes):
        attribute_names = []
        for field_name in dir(SectionAttributes):
            if field_name.startswith("S_ATTR_"):
                try:
                    value = getattr(SectionAttributes, field_name)
                    if (attributes & value) != 0:
                        attribute_names.append(field_name[7:])
                except Exception as e:
                    pass
        return attribute_names

# Example usage:
print(SectionAttributes.get_attribute_names(0xffffff00))
