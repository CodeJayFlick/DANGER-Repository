Here is the equivalent Python code:

```
class DWARFSectionNames:
    DEBUG_INFO = "debug_info"
    DEBUG_TYPES = "debug_types"
    DEBUG_ABBREV = "debug_abbrev"
    DEBUG_ARRANGES = "debug_arranges"
    DEBUG_LINE = "debug_line"
    DEBUG_FRAME = "debug_frame"
    DEBUG_LOC = "debug_loc"
    DEBUG_STR = "debug_str"
    DEBUG_RANGES = "debug_ranges"
    DEBUG_PUBNAMES = "debug_pubnames"
    DEBUG_PUBTYPES = "debug_pubtypes"
    DEBUG_MACINFO = "debug_macinfo"

    MINIMAL_DWARF_SECTIONS = [DEBUG_INFO, DEBUG_ABBREV]
```

Note that in Python, we don't need to use `public` or `final`, as these are Java-specific keywords. We also don't need an explicit package declaration, as Python's module system is different from Java's.