Here is a translation of the Java code into equivalent Python:

```Python
class AndroidBootLoaderAnalyzer:
    def __init__(self):
        self.name = "Android Boot Loader"
        self.description = "Annotates the Android Boot Loader header components"

    def get_default_enablement(self, program):
        return AndroidBootLoaderConstants.is_boot_loader(program)

    def can_analyze(self, program):
        return AndroidBootLoaderConstants.is_boot_loader(program)

    def register_options(self, options, program):
        pass

    def added(self, program, address_set_view, task_monitor, message_log):
        try:
            header_address = program.min_address
            provider = MemoryByteProvider(program.memory, header_address)
            reader = BinaryReader(provider, not program.language.is_big_endian())
            header = AndroidBootLoaderHeader(reader)
            data_type = header.to_data_type()
            if (data := program.listing.create_data(header_address, data_type)) is None:
                message_log.append("Unable to apply header data, stopping.")
                return False
            symbol_table = program.symbol_table
            if (symbol := symbol_table.get_primary_symbol(header_address)) is None:
                symbol_table.create_label(header_address, header.magic, SourceType.ANALYSIS)
            else:
                symbol.name = header.magic, SourceType.ANALYSIS

            running_offset = header.start_offset
            for image_info in header.image_info_list():
                address = program.address_space.get_address(running_offset)
                symbol_table.create_label(address, image_info.name, SourceType.ANALYSIS)
                program.bookmark_manager.set_bookmark(
                    address,
                    BookmarkType.ANALYSIS,
                    "boot",
                    image_info.name
                )
                running_offset += image_info.size

            return True
        except Exception as e:
            message_log.append_exception(e)

    def __str__(self):
        return f"{self.name} - {self.description}"
```

Please note that this is a translation and not an exact equivalent. Python has different syntax, data types, and libraries compared to Java.