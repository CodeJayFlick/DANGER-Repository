class AppleSingleDoubleBinaryAnalysisCommand:
    def __init__(self):
        self.messages = MessageLog()

    def analysisWorkerCallback(self, program: Program, workerContext: Object, monitor: TaskMonitor) -> bool:
        try:
            provider = MemoryByteProvider(program.get_memory(), program.get_address_factory().get_default_address_space())
            header = AppleSingleDouble(provider)
            address = to_addr(0)
            header_dt = header.to_data_type()
            create_data(address, header_dt)
            set_plate_comment(address, header_dt.name)
            create_fragment(header_dt.name, address, header_dt.length)
            address += header_dt.length

            entry_list = header.get_entry_list()
            for descriptor in entry_list:
                if monitor.is_cancelled():
                    break
                descriptor_dt = descriptor.to_data_type()
                create_data(address, descriptor_dt)
                set_plate_comment(address, descriptor_dt.name)
                create_fragment(descriptor_dt.name, address, descriptor_dt.length)
                address += descriptor_dt.length

                name = EntryDescriptorID.convert_entry_id_to_name(descriptor.entry_id)
                create_fragment(name, to_addr(descriptor.offset), descriptor.length)

                entry_object = descriptor.entry
                if descriptor.entry_id == EntryDescriptorID.ENTRY_RESOURCE_FORK:
                    markup((ResourceHeader)entry_object, descriptor)

            remove_empty_fragments()

            return True

        except MacException as e:
            self.messages.append_msg("Not a binary AppleSingleDouble program: AppleSingleDouble header not found.")
            return False


    def get_worker_name(self):
        return self.name()


    def apply_to(self, program: Program, monitor: TaskMonitor) -> bool:
        set(program, monitor)

        # Modify program and prevent events from triggering follow-on analysis
        manager = AutoAnalysisManager.get_analysis_manager(current_program)
        return manager.schedule_worker(self, None, False, monitor)


    def can_apply(self, program: Program) -> bool:
        try:
            memory = program.get_memory()

            magic_number = memory.get_int(program.get_address_factory().get_default_address_space().get_address(0))

            if magic_number == AppleSingleDouble.SINGLE_MAGIC_NUMBER or \
               magic_number == AppleSingleDouble.DOUBLE_MAGIC_NUMBER:
                return True

        except Exception as e:
            # expected, ignore
            pass

        return False


    def get_messages(self):
        return self.messages


    def name(self) -> str:
        return "Apple Single/Double Header Annotation"


    def markup(self, header: ResourceHeader, descriptor: EntryDescriptor) -> None:
        try:
            header_dt = header.to_data_type()
            address = to_addr(descriptor.offset)
            create_data(address, header_dt)
            set_plate_comment(address, header_dt.name)
            create_fragment(header_dt.name, address, header_dt.length)

            resource_data_address = to_addr(header.resource_data_offset + descriptor.offset)
            markup_resource_data(resource_data_address, header.resource_data_length())

            map_address = markup_resource_map(header, descriptor, header.get_map())
        except Exception as e:
            # expected, ignore
            pass


    def markup_cfm(self, type: ResourceType, resource_data_address: Address) -> None:
        if type.type != ResourceTypes.TYPE_CF_RG:
            return

        entries = type.reference_list()
        if len(entries) != 1:
            raise AssertionError()

        data_offset = entries[0].data_offset
        address = resource_data_address.add(data_offset + 4)
        cfrag_resource = (CFragResource)type.resource_object
        dt = cfrag_resource.to_data_type()
        create_data(address, dt)
        set_plate_comment(address, dt.name)
        create_fragment(dt.name, address, dt.length)


    def markup_reference_list_entry(self, map: ResourceMap, address: Address, type: ResourceType, resource_data_address: Address) -> None:
        try:
            module = self.create_module("ResourceListEntry")
            id = 0
            entry_address = address.add(map.resource_type_list_offset + type.offset_to_reference_list)
            reference = type.reference_list()
            for entry in reference:
                if monitor.is_cancelled():
                    return

                dt = entry.to_data_type()
                create_data(entry_address, dt)
                module.create_fragment(dt.name, entry_address, dt.length)

                name = ""
                if entry.name is not None:
                    name += " - " + entry.name
                set_plate_comment(entry_address, name)
                id += 1

                data_address = resource_data_address.add(entry.data_offset)
                set_plate_comment(data_address, type.type_string + " - " + entry.name)

        except Exception as e:
            # expected, ignore
            pass


    def markup_resource_name_list(self, map: ResourceMap, address: Address) -> None:
        try:
            while True:
                if monitor.is_cancelled():
                    break

                create_data(address, PascalString255DataType())
                data = get_data_at(address)
                module.create_fragment("ResourceNameList", address, data.length)

                address += data.length
        except Exception as e:
            # expected, ignore
            pass


    def markup_resource_data(self, address: Address) -> None:
        try:
            module = self.create_module("ResourceData")
            size = 0
            id = 0

            while True:
                if monitor.is_cancelled():
                    break

                create_data(address, DWordDataType())
                set_eol_comment(address, "Data Length")

                length = get_int(address)
                module.create_fragment("", address, length + 4)

                size += length + 4
                address += length + 4

        except Exception as e:
            # expected, ignore
            pass


    def create_module(self, name: str) -> ProgramModule:
        try:
            return current_program.get_listing().get_default_root_module().create_module(name)
        except DuplicateNameException as e:
            return find_group(current_program.get_listing().get_default_root_module(), name)


    def find_group(self, module: ProgramModule, name: str) -> Group:
        groups = module.get_children()
        for group in groups:
            if monitor.is_cancelled():
                return None

            if group.name == name:
                return group
        return None


    def remove_empty_fragments(self):
        try:
            monitor.set_message("Removing empty fragments...")
            tree_names = current_program.get_listing().get_tree_names()
            for tree_name in tree_names:
                root_module = current_program.get_listing().get_root_module(tree_name)
                children = root_module.get_children()

                for child in children:
                    if isinstance(child, ProgramFragment):
                        fragment = child
                        if fragment.is_empty():
                            root_module.remove_child(fragment.name)

        except Exception as e:
            # expected, ignore
            pass


    def set(self, program: Program, monitor: TaskMonitor) -> None:
        return


    @staticmethod
    def to_addr(address: int):
        return address

    @staticmethod
    def create_data(address: Address, dt: DataType):
        return

    @staticmethod
    def get_int(address: Address):
        return 0

    @staticmethod
    def set_plate_comment(address: Address, comment: str):
        return

    @staticmethod
    def create_fragment(name: str, address: Address, length: int):
        return

    @staticmethod
    def find_group(module: ProgramModule, name: str) -> Group:
        return None


class MessageLog:

    def append_msg(self, message: str):
        pass


# Python doesn't support static methods or properties. It supports only instance and class methods.
