class MultEntSubModel:
    NAME = "Multiple Entry"

    def __init__(self, program):
        self.program = program
        self.listing = program.get_listing()
        self.include_externals = False
        self.found_msubs = {}
        self.bb_model = None

    @staticmethod
    def get_name():
        return MultEntSubModel.NAME


class CodeBlock:
    pass


def add_sources(monitor, entry_pt_list, todo_list, bblock):
    src_iter = bblock.get_sources(monitor)
    is_source = True
    while src_iter.has_next():
        code_block_reference = src_iter.next()
        flow_type = code_block_reference.get_flow_type()
        if flow_type.is_jump() or flow_type.is_fallthrough():
            todo_list.add_last(code_block_reference.get_destination_address())
        elif flow_type.is_call():
            is_entry = True
    if is_source or is_entry:
        entry_pt_list.append(bblock.get_min_address())


def add_destinations(monitor, todo_list, bblock):
    code_block_reference_iter = bblock.get_destinations(monitor)
    while code_block_reference_iter.has_next():
        code_block_reference = code_block_reference_iter.next()
        if code_block_reference.is_jump() or code_block_reference.is_fallthrough():
            todo_list.add_last(code_block_reference.get_destination_address())


def get_code_blocks_containing(addr_set, monitor):
    return [CodeBlock]


class AddressSet:
    def __init__(self):
        pass


class CodeBlockReferenceIterator:
    @staticmethod
    def has_next():
        return True

    @staticmethod
    def next():
        pass


class FlowType:
    UNKNOWN = 0
    INVALID = 1
    FLOW = 2


def get_flow_type(block, monitor):
    if isinstance(block.model(), MultEntSubModel):
        return RefType.FLOW
    else:
        raise Exception("Invalid block model")


class CodeBlockReferenceIterator:
    @staticmethod
    def has_next():
        return True

    @staticmethod
    def next():
        pass


def get_sources(block, monitor):
    if isinstance(block.model(), MultEntSubModel):
        return SubroutineSourceReferenceIterator(block, monitor)
    else:
        raise Exception("Invalid block model")


class CodeBlockReferenceIterator:
    @staticmethod
    def has_next():
        return True

    @staticmethod
    def next():
        pass


def get_destinations(block, monitor):
    if isinstance(block.model(), MultEntSubModel):
        return SubroutineDestReferenceIterator(block, monitor)
    else:
        raise Exception("Invalid block model")


class AddressSetView:
    def __init__(self, address_set):
        self.address_set = address_set

    @staticmethod
    def get_address_set(address_set):
        return AddressSetView(address_set)


def get_sub_from_cache(addr):
    map_objs = MultEntSubModel.found_msubs.get_objects(addr)
    if len(map_objs) == 0:
        return None
    else:
        return map_objs[0]


class SimpleBlockModel:
    def __init__(self, program):
        self.program = program

    @staticmethod
    def get_first_code_block_containing(addr, monitor):
        pass


def main():
    # Create a MultEntSubModel instance.
    mult_ent_sub_model = MultEntSubModel(None)

    # Get the code block that has an entry point at addr.
    code_block_at_addr = mult_ent_sub_model.get_code_block_at(0x12345678, None)
    
    if code_block_at_addr is not None:
        print("Code Block: ", code_block_at_addr)


if __name__ == "__main__":
    main()
