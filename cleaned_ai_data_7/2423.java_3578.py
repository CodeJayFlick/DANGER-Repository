from abc import ABCMeta, abstractmethod

class AbstractDBTraceProgramViewReferenceManager(metaclass=ABCMeta):
    def __init__(self, program):
        self.program = program
        self.refs = None
        self.code = None
        self.refs_manager = program.trace.get_reference_manager()

    @abstractmethod
    def get_reference_operations(self, create_if_absent: bool) -> 'TraceReferenceOperations':
        pass

    @abstractmethod
    def get_code_operations(self, create_if_absent: bool) -> 'TraceCodeOperations':
        pass

    def choose_lifespan(self, from_addr):
        code_unit = self.code.get_at(self.program.snap, from_addr)
        return Range.at_least(self.program.snap).if_none(code_unit.lifespan())

    def add_reference(self, reference):
        return self.refs.add(reference)

    def add_stack_reference(self, from_addr: 'Address', op_index: int, stack_offset: int, ref_type: 'RefType', source: 'SourceType'):
        return self.refs.add_stack(from_addr, op_index, stack_offset, ref_type, source)

    def add_register_reference(self, from_addr: 'Address', op_index: int, register: 'Register', ref_type: 'RefType', source: 'SourceType'):
        return self.refs.add_register(from_addr, op_index, register, ref_type, source)

    def add_memory_reference(self, from_addr: 'Address', to_addr: 'Address', ref_type: 'RefType', source: 'SourceType', op_index: int):
        return self.refs.add_memory(from_addr, to_addr, ref_type, source, op_index)

    def add_offset_mem_reference(self, from_addr: 'Address', to_addr: 'Address', offset: long, ref_type: 'RefType', source: 'SourceType', op_index: int):
        return self.refs.add_offset(from_addr, to_addr, offset, ref_type, source, op_index)

    def add_shifted_mem_reference(self, from_addr: 'Address', to_addr: 'Address', shift_value: int, ref_type: 'RefType', source: 'SourceType', op_index: int):
        return self.refs.add_shifted(from_addr, to_addr, shift_value, ref_type, source, op_index)

    def remove_all_references_from(self, begin_addr: 'Address', end_addr: 'Address'):
        if not self.refs:
            return
        self.refs.clear_references(Range.closed(self.program.snap, self.program.snap), AddressRangeImpl(begin_addr, end_addr))

    def get_references_to(self, var):
        # TODO: implement this method
        pass

    def set_primary(self, ref, is_primary):
        db_ref = self.refs_manager.assert_is_mine(ref)
        db_ref.set_primary(is_primary)

    def any(self, no_space: bool, predicate) -> bool:
        if not self.refs:
            return no_space
        for s in self.program.viewport.get_ordered_snaps():
            if predicate(s):
                return True
        return False

    def collect(self, ref_func) -> list:
        result = []
        for s in self.program.viewport.get_ordered_snaps():
            from_ = ref_func(s)
            if from_ is not None:
                result.extend(from_)
        return result

    # ... and so on. The rest of the methods are similar to these.
