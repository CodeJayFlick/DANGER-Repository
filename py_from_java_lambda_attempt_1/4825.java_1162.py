Here is the equivalent Python code:

```Python
class MachHeaderFileTypes:
    MH_OBJECT = 1
    MH_EXECUTE = 2
    MH_FVMLIB = 3
    MH_CORE = 4
    MH_PRELOAD = 5
    MH_DYLIB = 6
    MH_DYLINKER = 7
    MH_BUNDLE = 8
    MH_DYLIB_STUB = 9
    MH_DSYM = 0xa
    MH_KEXT_BUNDLE = 0xb

    @staticmethod
    def get_file_type_name(file_type):
        for field in MachHeaderFileTypes.__dict__:
            if field.startswith("MH_"):
                value = getattr(MachHeaderFileTypes, field)
                if value == file_type:
                    return field[3:]
        return f"Unrecognized file type: 0x{file_type:x}"

    @staticmethod
    def get_file_type_description(file_type):
        descriptions = {
            MachHeaderFileTypes.MH_OBJECT: "Relocatable Object File",
            MachHeaderFileTypes.MH_EXECUTE: "Demand Paged Executable File",
            MachHeaderFileTypes.MH_FVMLIB: "Fixed VM Shared Library File",
            MachHeaderFileTypes.MH_CORE: "Core File",
            MachHeaderFileTypes.MH_PRELOAD: "Preloaded Executable File",
            MachHeaderFileTypes.MH_DYLIB: "Dynamically Bound Shared Library",
            MachHeaderFileTypes.MH_DYLINKER: "Dynamic Link Editor",
            MachHeaderFileTypes.MH_BUNDLE: "Dynamically Bound Bundle File",
            MachHeaderFileTypes.MH_DYLIB_STUB: "Shared Library Stub for Static Linking Only",
            MachHeaderFileTypes.MH_DSYM: "Companion file with only debug sections",
            MachHeaderFileTypes.MH_KEXT_BUNDLE: "x86 64 Kernel Extension"
        }
        return descriptions.get(file_type, f"Unrecognized file type: 0x{file_type:x}")
```

This Python code defines a class `MachHeaderFileTypes` that contains constants for different types of Mach-O files. The two static methods `get_file_type_name` and `get_file_type_description` are equivalent to the Java methods with the same names, but they use dictionary lookups instead of reflection.