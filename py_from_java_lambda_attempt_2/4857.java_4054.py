Here is the equivalent Python code:

```Python
class EntryDescriptorID:
    ENTRY_DATA_FORK = 1
    ENTRY_RESOURCE_FORK = 2
    ENTRY_REAL_NAME = 3
    ENTRY_COMMENT = 4
    ENTRY_ICON_BW = 5
    ENTRY_ICON_COLOR = 6
    ENTRY_FILE_DATE_INFO = 7
    ENTRY_FINDER_INFO = 8
    ENTRY_MAC_FILE_INFO = 9
    ENTRY_PRODOS_FILE_INFO = 0xa
    ENTRY_MSDOS_FILE_INFO = 0xb
    ENTRY_SHORT_NAME = 0xc
    ENTRY_AFP_FILE_INFO = 0xd
    ENTRY_DIRECTORY_ID = 0xe

def convert_entry_id_to_name(entry_id):
    for field in EntryDescriptorID.__dict__:
        if field.startswith("ENTRY_"):
            value = getattr(EntryDescriptorID, field)
            if value == entry_id:
                return field[7:]
    return f"Unrecognized entry id: 0x{entry_id:x}"
```

Note that Python does not have a direct equivalent to Java's `public final static` keywords. In Python, these are implied by the class definition and do not need to be explicitly stated.