Here is the translation of the Java code into Python:

```Python
class ObjectiveC2ClassAnalyzer:
    def __init__(self):
        self.name = "Objective-C 2 Class"
        self.description = "An analyzer for extracting and annotating Objective-C 2.0 class structure information."
        super().__init__(self.name, self.description)

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog) -> bool:
        return self.process_objective_c_2(program, monitor, log)

    def can_analyze(self, program: Program) -> bool:
        return ObjectiveC2Constants.is_objective_c_2(program)

    def process_image_info(self, state: 'ObjectiveC2State', reader: BinaryReader):
        print("Processing Image Info...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_IMAGE_INFO)
        if block is None:
            return
        address = block.get_start()
        reader.set_pointer_index(address.offset)
        image_info = ObjectiveC2ImageInfo(state, reader)
        image_info.apply_to()

    def process_category_list(self, state: 'ObjectiveC2State', reader: BinaryReader):
        print("Processing Category List...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_CATEGORY_LIST)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // state.pointer_size
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            protocol_address = ObjectiveC1Utilities.create_pointer_and_return_address_being_referenced(state.program, address)
            reader.set_pointer_index(protocol_address.offset)
            category = ObjectiveC2Category(state, reader)
            namespace = ObjectiveC1Utilities.create_namespace(state.program, "Protocols", category.name)
            category.apply_to(namespace)
            address += state.pointer_size

    def process_protocol_list(self, state: 'ObjectiveC2State', reader: BinaryReader):
        print("Processing Protocol List...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_PROTOCOL_LIST)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // state.pointer_size
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            protocol_address = ObjectiveC1Utilities.create_pointer_and_return_address_being_referenced(state.program, address)
            reader.set_pointer_index(protocol_address.offset)
            protocol = ObjectiveC2Protocol(state, reader)
            namespace = ObjectiveC1Utilities.create_namespace(state.program, "Protocols", protocol.name)
            protocol.apply_to(namespace)
            address += state.pointer_size

    def process_class_list(self, state: 'ObjectiveC2State', reader: BinaryReader):
        print("Processing Class List...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_CLASS_LIST)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // state.pointer_size
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            class_address = ObjectiveC1Utilities.create_pointer_and_return_address_being_referenced(state.program, address)
            reader.set_pointer_index(class_address.offset)
            clazz = ObjectiveC2Class(state, reader)
            clazz.apply_to()
            address += state.pointer_size

    def process_message_references(self, state: 'ObjectiveC2State', reader: BinaryReader):
        print("Processing Message References...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_MESSAGE_REFS)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // ObjectiveC2MessageReference.SIZEOF(state)
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            reader.set_pointer_index(address.offset)
            message_ref = ObjectiveC2MessageReference(state, reader)
            dt = message_ref.to_data_type()
            data = state.program.get_listing().create_data(address, dt)
            sel_data = data.get_component(1)
            sel_address = sel_data.value
            sel_string_data = state.program.get_listing().get_data_at(sel_address)
            sel_string = sel_string_data.value
            ObjectiveC1Utilities.create_symbol(state.program, None, sel_string + "_" + message_ref.name, address)
            address += dt.length

    def process_selector_references(self, state: 'ObjectiveC2State'):
        print("Processing Selector References...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_SELECTOR_REFS)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // state.pointer_size
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            ObjectiveC1Utilities.create_pointer_and_return_address_being_referenced(state.program, address)
            address += state.pointer_size

    def process_non_lazy_class_references(self, state: 'ObjectiveC2State'):
        print("Processing Non-Lazy Class References...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_NON_LAZY_CLASS_LIST)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // state.pointer_size
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            class_address = ObjectiveC1Utilities.create_pointer_and_return_address_being_referenced(state.program, address)
            reader = BinaryReader(None, False)
            reader.set_pointer_index(class_address.offset)
            clazz = ObjectiveC2Class(state, reader)
            namespace = ObjectiveC1Utilities.create_namespace(state.program, "Protocols", clazz.name)
            clazz.apply_to(namespace)
            address += state.pointer_size

    def process_super_references(self, state: 'ObjectiveC2State'):
        print("Processing Super References...")
        block = state.program.get_memory().get_block(ObjectiveC2Constants.OBJC2_SUPER_REFS)
        if block is None:
            return
        ObjectiveC1Utilities.clear(state, block)
        count = block.size() // state.pointer_size
        state.monitor.initialize(count)
        address = block.get_start()
        for i in range(count):
            if state.monitor.is_cancelled():
                break
            state.monitor.set_progress(i)
            class_address = ObjectiveC1Utilities.create_pointer_and_return_address_being_referenced(state.program, address)
            reader = BinaryReader(None, False)
            reader.set_pointer_index(class_address.offset)
            clazz = ObjectiveC2Class(state, reader)
            namespace = ObjectiveC1Utilities.create_namespace(state.program, "Protocols", clazz.name)
            clazz.apply_to(namespace)
            address += state.pointer_size

    def set_data_and_ref_blocks_read_only(self, state: 'ObjectiveC2State'):
        memory = state.program.get_memory()
        data_block = memory.get_block(ObjectiveC2Constants.OBJC2_DATA)
        if data_block is not None:
            data_block.set_write(False)

        class_refs_block = memory.get_block(ObjectiveC2Constants.OBJC2_CLASS_REFS)
        if class_refs_block is not None:
            class_refs_block.set_write(False)

        message_refs_block = memory.get_block(ObjectiveC2Constants.OBJC2_MESSAGE_REFS)
        if message_refs_block is not None:
            message_refs_block.set_write(False)

        selector_refs_block = memory.get_block(ObjectiveC2Constants.OBJC2_SELECTOR_REFS)
        if selector_refs_block is not None:
            selector_refs_block.set_write(False)

        super_refs_block = memory.get_block(ObjectiveC2Constants.OBJC2_SUPER_REFS)
        if super_refs_block is not None:
            super_refs_block.set_write(False)

        protocol_refs_block = memory.get_block(ObjectiveC2Constants.OBJC2_PROTOCOL_REFS)
        if protocol_refs_block is not None:
            protocol_refs_block.set_write(False)