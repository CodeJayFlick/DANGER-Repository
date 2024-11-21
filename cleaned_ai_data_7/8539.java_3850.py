class DataSymbolApplier:
    def __init__(self, applicator: 'PdbApplicator', iter):
        self.applicator = applicator
        self.iter = iter
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, AbstractDataMsSymbol):
            raise AssertException(f"Invalid symbol type: {abstract_symbol.__class__.__name__}")
        self.symbol = abstract_symbol

    def apply_to(self, applier) -> None:
        if isinstance(applier, FunctionSymbolApplier):
            function_symbol_applier = applier
            ms_type_applier = self.applicator.get_ms_type_applier()
            data_type = ms_type_applier.get_data_type()
            name = self.symbol.name
            address = self.applicator.get_address(self.symbol)
            if not self.applicator.is_invalid_address(address, name):
                function_symbol_applier.set_local_variable(address, name, data_type)

    def apply(self) -> None:
        symbol_address = self.applicator.get_address(self.symbol)
        if not self.applicator.is_invalid_address(symbol_address, self.symbol.name):
            record_number = self.symbol.type_record_number
            self.applicator.create_symbol(symbol_address, self.symbol.name, True)
            create_data(symbol_address, record_number)

    def get_ms_type_applier(self) -> 'MsTypeApplier':
        return self.applicator.get_ms_type_applier(self.symbol.type_record_number)

    def create_data(self, address: Address, data_type: DataType, length: int = -1):
        existing_data = None
        code_unit = self.applicator.program.listing.code_unit_containing(address)
        if code_unit is not None:
            if isinstance(code_unit, Instruction) or address != code_unit.address:
                print(f"Warning: Did not create data type '{data_type.get_display_name()}' at 0x{address} due to conflict")
                return
            existing_data = Data(existing_data)

        if data_type is None:
            return

        if length <= 0 and self.symbol.length <= 0:
            print(f"Unknown dataTypeLength specified at address {address} for {data_type.get_display_name()}")
            return

        if existing_data is not None:
            try:
                self.applicator.program.listing.clear_code_units(address, address.add(length - 1), False)
                self.applicator.program.listing.create_data(address, data_type, length)
            except (CodeUnitInsertionException | DataTypeConflictException) as e:
                print(f"Unable to create {data_type.get_display_name()} at 0x{address}: {e}")
        else:
            try:
                self.applicator.program.listing.clear_code_units(address, address.add(length - 1), False)
                self.applicator.program.listing.create_data(address, data_type, length)
            except (CodeUnitInsertionException | DataTypeConflictException) as e:
                print(f"Unable to replace {data_type.get_display_name()} at 0x{address}: {e}")
        else:
            existing_data = Data(existing_data)

    def is_data_replaceable(self, data: 'Data') -> bool:
        if isinstance(data.data_type, Pointer):
            pointer = data.data_type
            return self.is_data_replaceable(pointer.get_data_type())
        elif isinstance(data.data_type, Array):
            array = data.data_type
            return self.is_data_replaceable(array.get_data_type())

    def is_equivalent(self, existing_data: 'Data', length: int, new_data_type: DataType) -> bool:
        if existing_data.has_string_value():
            if isinstance(new_data_type, ArrayDataType):
                array = new_data_type
                if isinstance(array.data_type, ArrayStringable):
                    return array.length == length

    def is_equivalent2(self, data_type1: 'DataType', data_type2: 'DataType') -> bool:
        if data_type1 == data_type2:
            return True
        elif data_type1 is None or data_type2 is None:
            return False
        elif isinstance(data_type1, Array):
            array = data_type1
            return self.is_equivalent2(array.get_data_type(), data_type2)
        elif isinstance(data_type1, Pointer):
            pointer = data_type1
            if isinstance(data_type2, Array):
                array = data_type2
                return self.is_equivalent2(pointer.get_data_type(), array.get_data_type())
        return data_type1.is_equivalent(data_type2)

class MsTypeApplier:
    def get_ms_type(self) -> 'MsType':
        pass

class PdbApplicator:
    def __init__(self):
        pass
