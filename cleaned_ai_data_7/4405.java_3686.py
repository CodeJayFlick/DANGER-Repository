class SymbolReferenceModel:
    ADDRESS_COLUMN = 0
    LABEL_COLUMN = 1
    SUBROUTINE_COLUMN = 2
    ACCESS_COLUMN = 3
    PREVIEW_COLUMN = 4

    ADDR_COL_NAME = "Address"
    LABEL_COL_NAME = "Label"
    SUBROUTINE_COL_NAME = "Subroutine"
    ACCESS_COL_NAME = "Access"
    PREVIEW_COL_NAME = "Preview"

    REFS_TO = 0
    INSTR_REFS_FROM = 1
    DATA_REFS_FROM = 2

    def __init__(self, block_model_service: 'BlockModelService', plugin_tool):
        super().__init__("Symbol References", plugin_tool)
        self.block_model_service = block_model_service

    @property
    def current_symbol(self) -> Symbol:
        return self._current_symbol

    @current_symbol.setter
    def current_symbol(self, symbol: Symbol):
        if symbol is not None and symbol.get_id() == self._current_symbol.get_id():
            self._current_symbol = None
        else:
            self._current_symbol = symbol
        self.reload()

    def get_description(self) -> str:
        if self.is_disposed:
            return None

        description = ""
        if self.current_symbol is not None:
            description += f"{self.current_symbol.get_name()}: "
        count = len(self.filtered_data)
        description += f"{count} Reference{'s' if count != 1 else ''}"
        return description

    def dispose(self):
        self.is_disposed = True
        super().dispose()

    @property
    def is_disposed(self) -> bool:
        return self._is_disposed

    @is_disposed.setter
    def is_disposed(self, value: bool):
        self._is_disposed = value

    def set_program(self, program: 'Program'):
        if self.is_disposed or program is None:
            super().set_program(None)
            self.ref_manager = None
        else:
            super().set_program(program)
            self.ref_manager = program.get_reference_manager()
        self.current_symbol = None
        self.reload()

    def symbol_added(self, symbol: Symbol):
        self.check_refs(symbol)

    def symbol_removed(self, symbol: Symbol):
        if self.current_symbol is not None and self.current_symbol.get_id() == symbol.get_id():
            self.set_current_symbol(None)
        else:
            pass

    def symbol_changed(self, symbol: Symbol):
        if self.current_symbol is not None and self.current_symbol.equals(symbol):
            return
        self.check_refs(symbol)

    @property
    def ref_manager(self) -> 'ReferenceManager':
        return self._ref_manager

    @ref_manager.setter
    def ref_manager(self, value: 'ReferenceManager'):
        self._ref_manager = value

    def show_references_to(self):
        self.show_ref_mode = SymbolReferenceModel.REFS_TO
        self.reload()

    def show_instruction_references_from(self):
        self.show_ref_mode = SymbolReferenceModel.INSTR_REFS_FROM
        self.reload()

    def show_data_references_from(self):
        self.show_ref_mode = SymbolReferenceModel.DATA_REFS_FROM
        self.reload()

    @property
    def filtered_data(self) -> list:
        return self._filtered_data

    @filtered_data.setter
    def filtered_data(self, value: list):
        self._filtered_data = value

    def do_load(self, accumulator: 'Accumulator[Reference]', monitor: TaskMonitor):
        if self.current_symbol is None or self.get_program() is None:
            return

        switch (self.show_ref_mode):
            case SymbolReferenceModel.REFS_TO:
                load_to_references(accumulator, monitor)
                break
            case SymbolReferenceModel.INSTR_REFS_FROM:
                load_from_references(accumulator, True, monitor)
                break
            case SymbolReferenceModel.DATA_REFS_FROM:
                load_from_references(accumulator, False, monitor)
                break

    def get_reference_type(self, type: RefType) -> str:
        if type == RefType.THUNK:
            return "Thunk"
        elif type.is_read() and type.is_write():
            return "RW"
        elif type.is_read():
            return "Read"
        elif type.is_write():
            return "Write"
        elif type.is_data():
            return "Data"
        elif type.is_call():
            return "Call"
        elif type.is_jump():
            if type.is_conditional:
                return "Branch"
            else:
                return "Jump"
        return "Unknown"

    def get_symbol(self, from_address: Address, symbol_name: str,
                   block_model_service: 'BlockModelService', program: 'Program') -> Symbol:
        symbol_table = program.get_symbol_table()
        iterator = symbol_table.get_symbols(symbol_name)
        while iterator.has_next():
            symbol = iterator.next()
            code_block_model = block_model_service.get_active_subroutine_model(program)
            blocks = get_code_blocks_containing_symbol(symbol, code_block_model)
            if blocks is None or len(blocks) == 0:
                continue
            for block in blocks:
                if block.contains(from_address):
                    return symbol

        return None

    def get_code_blocks_containing_symbol(self, symbol: Symbol,
                                            code_block_model: 'CodeBlockModel') -> list:
        return code_block_model.get_code_blocks_containing(symbol)

    @property
    def show_ref_mode(self) -> int:
        return self._show_ref_mode

    @show_ref_mode.setter
    def show_ref_mode(self, value: int):
        self._show_ref_mode = value

    def reload(self):
        pass

class SubroutineTableColumn(AbstractProgramBasedDynamicTableColumn[Reference, str]):
    def __init__(self):
        super().__init__()

    def get_column_name(self) -> str:
        return "Subroutine"

    def get_value(self, row_object: Reference, settings: Settings,
                  program: 'Program', service_provider: ServiceProvider) -> str:
        block_model_service = service_provider.get_service(BlockModelService)
        code_block_model = getCode_block_model(program, block_model_service)
        return get_subroutine_name(row_object, block_model_service, program, code_block_model)

    def get_program_location(self, row_object: Reference, settings: Settings,
                             program: 'Program', service_provider: ServiceProvider) -> ProgramLocation:
        block_model_service = service_provider.get_service(BlockModelService)
        code_block_model = getCode_block_model(program, block_model_service)
        subroutine_name = get_subroutine_name(row_object, block_model_service, program, code_block_model)
        if subroutine_name is None:
            return None
        symbol = get_symbol(row_object.from_address, subroutine_name,
                            block_model_service, program)
        if symbol is not None:
            return symbol.get_program_location()
        return None

    def getCodeBlockModel(self, program: 'Program', service_provider: ServiceProvider) -> 'CodeBlockModel':
        cached_model = self._cached_model
        if cached_model is None or program != self._cached_program:
            code_block_model = service_provider.get_service(BlockModelService).get_active_subroutine_model(program)
            self._cached_model = code_block_model
            self._cached_program = program

        return self._cached_model

    def getSubroutineName(self, row_object: Reference,
                          block_model_service: 'BlockModelService', program: 'Program',
                          code_block_model: 'CodeBlockModel') -> str:
        if row_object.from_address is None or code_block_model is None:
            return None
        blocks = getCode_blocks_containing_address(row_object.from_address, code_block_model)
        if len(blocks) > 0:
            return blocks[0].name

        return None

    def getCodeBlocksContainingAddress(self, address: Address,
                                        code_block_model: 'CodeBlockModel') -> list:
        try:
            return code_block_model.get_code_blocks_containing(address)
        except CancelledException as e:
            pass
