class TrampolineSymbolApplier:
    def __init__(self, applicator: 'PdbApplicator', iter):
        self.applicator = applicator
        self.iter = iter
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, TrampolineMsSymbol):
            raise AssertionError(f"Invalid symbol type: {abstract_symbol.__class__.__name__}")
        self.symbol = abstract_symbol

    def apply_to(self, applier):
        # Do nothing.
        pass

    def apply(self) -> None:
        try:
            if not self.applicator.is_invalid_address(target_address=self.symbol.get_segment_target(), target_name="thunk target"):
                target_function = create_new_function(start_address=target_address, size=1)
            if not self.applicator.is_invalid_address(symbol_address=self.symbol.get_symbol_address(), name="thunk symbol"):
                thunk_function = create_new_function(start_address=symbol_address, size=self.symbol.size_of_thunk())
            if target_function and thunk_function:
                thunk_function.set_thunked_function(target_function)

        except CancelledException as e:
            raise
        except PdbException as e:
            raise

    def create_new_function(self, start_address: Address, size: int) -> Function:
        address_set = AddressSet(start_address=start_address, end_address=start_address.add(size))
        if self.applicator.get_program().get_listing().get_instruction_at(start_address) is None:
            cmd = DisassembleCommand(address_set=address_set, cancel_only=True)
            try:
                cmd.apply_to(program=self.applicator.get_program(), monitor=self.applicator.get_cancel_only_wrapping_monitor())
            except Exception as e:
                print(f"Failed to apply function at address {start_address}: {e}")
        function = self.applicator.get_program().get_listing().get_function_at(start_address)
        if function is not None:
            return function
        fun_cmd = CreateFunctionCmd(start_address=start_address)
        try:
            fun_cmd.apply_to(program=self.applicator.get_program(), monitor=self.applicator.get_cancel_only_wrapping_monitor())
        except Exception as e:
            self.applicator.append_log_msg(f"Failed to apply function at address {start_address}: {e}")
        return fun_cmd.function


class PdbApplicator:
    def __init__(self):
        pass

    def get_program(self) -> 'Program':
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")

    def is_invalid_address(self, target_name: str = None) -> bool:
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")

    def append_log_msg(self, message):
        pass

class Program:
    def __init__(self):
        pass

    def get_listing(self) -> 'Listing':
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")


class Listing:
    def __init__(self):
        pass

    def get_function_at(self, address: Address) -> Function:
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_instruction_at(self, address: Address) -> 'Instruction':
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")


class Instruction:
    pass


class TrampolineMsSymbol:
    def __init__(self):
        pass

    @property
    def segment_target(self) -> int:
        return 0

    @property
    def offset_target(self) -> int:
        return 0

    @property
    def size_of_thunk(self) -> int:
        return 1


class Address:
    def __init__(self, value: int):
        self.value = value

    def add(self, other: 'Address') -> 'Address':
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")


class Function:
    pass


class CreateFunctionCmd:
    def __init__(self, start_address: Address):
        self.start_address = start_address
        self.function = None

    def apply_to(self, program: 'Program', monitor) -> bool:
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")

    @property
    def function(self) -> Function:
        return self.function


class DisassembleCommand:
    def __init__(self, address_set: AddressSet, cancel_only=False):
        self.address_set = address_set
        self.cancel_only = cancel_only

    def apply_to(self, program: 'Program', monitor) -> None:
        # TODO: implement this method
        raise NotImplementedError("Method not implemented")


class CancelledException(Exception):
    pass


class PdbException(Exception):
    pass
