Here is the translation of the given Java code into equivalent Python:

```Python
class DebugDirectoryParser:
    IMAGE_DEBUG_TYPE_UNKNOWN = 0
    IMAGE_DEBUG_TYPE_COFF = 1
    IMAGE_DEBUG_TYPE_CODEVIEW = 2
    IMAGE_DEBUG_TYPE_FPO = 3
    IMAGE_DEBUG_TYPE_MISC = 4
    IMAGE_DEBUG_TYPE_EXCEPTION = 5
    IMAGE_DEBUG_TYPE_FIXUP = 6
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8
    IMAGE_DEBUG_TYPE_BORLAND = 9
    IMAGE_DEBUG_TYPE_RESERVED10 = 10
    IMAGE_DEBUG_TYPE_CLSID = 11

    def __init__(self):
        self.debug_format_list = []
        self.misc_debug = None
        self.code_view_debug = None
        self.coff_debug = None
        self.fixup_debug = None

    @staticmethod
    def create_debug_directory_parser(reader, ptr, size, validator) -> 'DebugDirectoryParser':
        parser = DebugDirectoryParser()
        parser.init_debug_directory_parser(reader, ptr, size, validator)
        return parser

    def init_debug_directory_parser(self, reader, ptr, size, validator):
        debug_formats_count = size // 28
        for i in range(debug_formats_count):
            debug_dir = DebugDirectory.create_debug_directory(reader, ptr, validator)
            if debug_dir.size_of_data == 0:
                break
            ptr += 28
            switch_type = debug_dir.type
            if switch_type == self.IMAGE_DEBUG_TYPE_CLSID:
                debug_dir.description = "CLSID"
            elif switch_type == self.IMAGE_DEBUG_TYPE_RESERVED10:
                debug_dir.description = "Reserved"
            elif switch_type == self.IMAGE_DEBUG_TYPE_BORLAND:
                debug_dir.description = "Borland"
            elif switch_type == self.IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
                debug_dir.description = "OMAPfromSrc"
            elif switch_type == self.IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
                debug_dir.description = "OMAPtoSrc"
            elif switch_type == self.IMAGE_DEBUG_TYPE_FIXUP:
                debug_dir.description = "Fixup"
                self.fixup_debug = DebugFixup.create_debug_fixup(reader, debug_dir, validator)
            elif switch_type == self.IMAGE_DEBUG_TYPE_EXCEPTION:
                debug_dir.description = "Exception"
            elif switch_type == self.IMAGE_DEBUG_TYPE_MISC:
                debug_dir.description = "Misc"
                self.misc_debug = DebugMisc.create_debug_misc(reader, debug_dir, validator)
            elif switch_type == self.IMAGE_DEBUG_TYPE_FPO:
                debug_dir.description = "FPO"
            elif switch_type == self.IMAGE_DEBUG_TYPE_CODEVIEW:
                debug_dir.description = "CodeView"
                self.code_view_debug = DebugCodeView.create_debug_codeview(reader, debug_dir, validator)
            elif switch_type == self.IMAGE_DEBUG_TYPE_COFF:
                debug_dir.description = "COFF"
                self.coff_debug = DebugCOFFSymbolsHeader.create_debug_coff_symbols_header(reader, debug_dir, validator)
            else:
                debug_dir.description = f"DebugType-{switch_type}"
            self.debug_format_list.append(debug_dir)

    def get_debug_directories(self):
        return [debug_directory for debug_directory in self.debug_format_list]

    def get_debug_misc(self) -> 'DebugMisc':
        return self.misc_debug

    def get_code_view_debug(self) -> 'DebugCodeView':
        return self.code_view_debug

    def get_coff_debug(self) -> 'DebugCOFFSymbolsHeader':
        return self.coff_debug

    def get_fixup_debug(self) -> 'DebugFixup':
        return self.fixup_debug
```

Please note that Python does not support switch-case statements like Java. Instead, you can use if-elif ladder or dictionaries to achieve the same functionality.