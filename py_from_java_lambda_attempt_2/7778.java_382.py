Here is the translation of the given Java code into equivalent Python:

```Python
class CreateRtti4BackgroundCmd:
    RTTI_4_NAME = "RTTI Complete Object Locator"

    def __init__(self, address_list: list, vf_table_blocks: list, validation_options, apply_options):
        self.vf_table_blocks = vf_table_blocks
        self.rtti4_locations = address_list

    @staticmethod
    def create_model(program: object) -> dict:
        if model is None or program != model['program'] or getDataAddress() != model['address']:
            model = {'program': program, 'address': getDataAddress(), 'validation_options': validation_options}
        return model

    def do_apply_to(self, program: object, task_monitor):
        good_rtti4_locations = []
        succeeded = False
        for addr in self.rtti4_locations:
            set_data_address(addr)
            succeeded |= super().doApplyTo(program, task_monitor)
            good_rtti4_locations.append(addr)

        if succeeded and apply_options.should_follow_data():
            create_associated_vf_tables(program, good_rtti4_locations, task_monitor)

        return succeeded

    def do_create_markup(self):
        program = model['program']
        rtti0_model = model['rtti0_model']

        if rtti0_model is None:
            return True
        
        # Label
        should_create_comment = apply_options.should_create_label()
        
        if should_create_comment:
            RttiUtil.create_symbol_from_demangled_type(program, getDataAddress(), rtti0_model, RTTI_4_NAME)

        # Plate Comment
        if should_create_comment:
            EHDataTypeUtilities.create_plate_comment_if_needed(program, RttiUtil.CONST_PREFIX + 
                    RttiUtil.get_descriptor_type_namespace(rtti0_model) + Namespace.DELIMITER, RTTI_4_NAME, None, getDataAddress(), apply_options)
        
        return True

    def create_associated_vf_tables(self, program: object, good_rtti4_locations: list, task_monitor):
        searcher = MemoryBytePatternSearcher("RTTI4 Vftables")
        found_vftables = {}

        for rtti4_address in good_rtti4_locations:
            bytes = ProgramMemoryUtil.get_direct_address_bytes(program, rtti4_address)
            
            add_byte_search_pattern(searcher, found_vftables, rtti4_address, bytes)

        search_set = AddressSet()
        for block in self.vf_table_blocks:
            search_set.add(block.start(), block.end())

        searcher.search(program, search_set, task_monitor)

        did_some = False
        for addr in good_rtti4_locations:
            monitor.check_cancelled()

            vftable_model = found_vftables.get(addr)
            
            if vftable_model is None:
                message = "No vfTable found for {} @ {}".format(Rtti4Model.DATA_TYPE_NAME, rtti4_address)
                handle_error_message(program, addr, message)
                continue
            
            create_vftable_cmd = CreateVfTableBackgroundCmd(vftable_model, apply_options)
            
            did_some |= create_vftable_cmd.apply_to(program, monitor)

        return did_some

    def add_byte_search_pattern(self, searcher: object, found_vftables: dict, rtti4_address: int, bytes):
        if bytes is None:
            return
        
        action = GenericMatchAction(rtti4_address)
        
        generic_match_pattern = GenericByteSequencePattern(bytes, action)

        searcher.add_pattern(generic_match_pattern)

    def apply_to(self, program: object) -> bool:
        monitor.check_cancelled()

        succeeded = False
        for addr in self.rtti4_locations:
            set_data_address(addr)
            
            succeeded |= super().doApplyTo(program, monitor)

        if succeeded and apply_options.should_follow_data():
            create_associated_vf_tables(program, self.rtti4_locations, monitor)

        return succeeded

    def handle_error_message(self, program: object, addr: int, message):
        # log the error
        pass

class MemoryBytePatternSearcher:
    def __init__(self, pattern_name):
        self.patterns = []

    def add_pattern(self, pattern):
        self.patterns.append(pattern)

    def search(self, program: object, address_set: AddressSet, task_monitor):
        for addr in address_set.get_addresses():
            monitor.check_cancelled()

            # perform the actual search
            pass

class GenericMatchAction:
    def __init__(self, target_address):
        self.target = target_address

    def apply(self, program: object, addr: int, match):
        if match is not None and match.address == self.target:
            # do something with the matched address
            pass

class GenericByteSequencePattern:
    def __init__(self, bytes, action):
        self.bytes = bytes
        self.action = action

    def get_bytes(self) -> list:
        return self.bytes

    def set_action(self, action: object):
        self.action = action

# usage example:

model = CreateRtti4BackgroundCmd([], [], validation_options, apply_options)
program = model.get_program()
address_list = [0x10000000]
vf_table_blocks = []

try:
    result = model.do_apply_to(program, task_monitor)
except CancelledException as e:
    print("Cancelled Exception: ", str(e))

model.create_associated_vf_tables(program, address_list, task_monitor)

# etc.
```

Please note that this is a direct translation of the given Java code into equivalent Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.