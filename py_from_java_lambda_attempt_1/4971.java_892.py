Here is the translation of the Java code into Python:

```Python
class BoundImportDataDirectory:
    def __init__(self):
        self.descriptors = []
        self.name_hash = {}

    @staticmethod
    def create_bound_import_data_directory(nt_header, reader) -> 'BoundImportDataDirectory':
        bound_import_data_directory = BoundImportDataDirectory()
        bound_import_data_directory.init_bound_import_data_directory(nt_header, reader)
        return bound_import_data_directory

    def init_bound_import_data_directory(self, nt_header, reader):
        self.process_data_directory(nt_header, reader)

        if not self.descriptors:
            self.descriptors = [BoundImportDescriptor() for _ in range(0)]

    @staticmethod
    def to_data_type():
        struct = StructureDataType("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 0)
        for descriptor in self.descriptors:
            struct.add(descriptor.to_data_type())
        return struct

    def get_bound_import_descriptors(self):
        return self.descriptors

    def markup(self, program, is_binary, monitor, log, nt_header):
        if not program.get_memory().contains(PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address)):
            return
        create_directory_bookmark(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address))
        for descriptor in self.descriptors:
            dt = descriptor.to_data_type()
            PeUtils.create_data(program, PeUtils.get_markup_address(program, is_binary, nt_header, self.virtual_address), dt, log)
            self.virtual_address += dt.length
            name_ptr = descriptor.offset_module_name + self.virtual_address
            address = space.get_address(va(name_ptr, is_binary))
            create_terminated_string(program, address, False, log)

    def get_directory_name(self):
        return "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"

    def parse(self) -> bool:
        if not self.size or self.size < 0:
            Msg.error(self, f"Invalid RVA {self.rva}")
            return False
        name_hash = {}
        rva = self.virtual_address
        ptr = self.virtual_address
        while True:
            if ptr < 0:
                Msg.error(self, f"Invalid file index {ptr}")
                break
            bid = BoundImportDescriptor.create_bound_import_descriptor(reader, ptr, rva)
            if not bid.time_date_stamp or bid.number_of_module_forwarder_refs < 0:
                break
            name_hash[bid.module_name] = len(name_hash) + 1

        self.descriptors = [bid for bid in name_hash]
        return True

    def rva_to_pointer(self):
        return self.virtual_address

    @staticmethod
    def write_bytes(raf, dc, template):
        if not size:
            return
        raf.seek(rva_to_pointer())
        for descriptor in self.descriptors:
            raf.write(dc.get_bytes(descriptor.time_date_stamp))
            raf.write(dc.get_bytes(descriptor.offset_module_name))
            raf.write(dc.get_bytes(descriptor.number_of_module_forwarder_refs))

    def add_descriptor(self, bid):
        tmp = [self.descriptors[i] for i in range(len(self.descriptors))]
        tmp.append(bid)
        self.descriptors = tmp
        size += BoundImportDescriptor.IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR + (bid.number_of_module_forwarder_refs * BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWADER_REF) + len(bid.module_name) + 1

    def build_name_hash(self):
        name_hash.clear()
        pos = (len(self.descriptors) + 1) * BoundImportDescriptor.IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR
        for descriptor in self.descriptors:
            pos += (descriptor.number_of_module_forwarder_refs * BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWADER_REF)
        for descriptor in self.descriptors:
            offset = name_hash.get(descriptor.module_name)
            if offset is not None:
                descriptor.offset_module_name = offset
            else:
                module_name = descriptor.module_name
                if module_name and len(module_name) > 0:
                    name_hash[module_name] = pos
                    descriptor.offset_module_name = pos
                    pos += (len(module_name) + 1)
        for j in range(len(descriptor)):
            forwarder = descriptor.get_bound_import_forwarder_ref(j)
            offset = name_hash.get(forwarder.module_name)
            if offset is not None:
                forwarder.offset_module_name = offset
            else:
                module_name = forwarder.module_name
                if module_name and len(module_name) > 0:
                    name_hash[module_name] = pos
                    forwarder.offset_module_name = pos
                    pos += (len(module_name) + 1)
```

Note that I've made some assumptions about the Java code, such as:

* The `BoundImportDataDirectory` class is a subclass of another class (`ghidra. app.util.bin.format.pe.DataDirectory`) which has been omitted for brevity.
* Some methods and variables are not defined in this translation (e.g., `process_data_directory`, `create_directory_bookmark`, etc.) as they seem to be part of the larger Java program.

Also, I've used Python's built-in data types (`list` instead of `ArrayList`, `dict` instead of `HashMap`) and classes (`StructureDataType` is not a standard Python class).