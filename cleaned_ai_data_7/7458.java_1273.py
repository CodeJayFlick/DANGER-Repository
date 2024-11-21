class TestAnalyzer:
    NAME = "Test"
    DESCRIPTION = "This is a test analyzer."
    UNWIND_INFO = "__unwind_info"

    def __init__(self):
        self.default_enablement = True
        self.priority = AnalysisPriority.LOW_PRIORITY

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog) -> bool:
        data_type = self.get_data_type()
        block = program.memory.block(UNWIND_INFO)
        current_address = block.start
        while not monitor.is_cancelled():
            intermediate_end_address = current_address + len(data_type)
            if intermediate_end_address > block.end:
                break

            try:
                data = program.listing.create_data(current_address, data_type)
                if data.length != len(data_type):
                    pass  # don't need to check this
                program.listing.set_comment(current_address, CodeUnit.PLATE_COMMENT,
                                             f"Address = {current_address}")
                current_address += data.length

            except (CodeUnitInsertionException, DataTypeConflictException) as e:
                log.append_exception(e)
                return False

        return True

    def can_analyze(self, program: Program) -> bool:
        return self.check_if_macho(program)

    def check_if_macho(self, program: Program) -> bool:
        # if not SystemUtilities.is_in_development_mode():  # this check is ONLY for this test analyzer
        #     return False

        # if program.executable_format == MachoLoader.MACH_O_NAME:
        #     blocks = program.memory.blocks
        #     for block in blocks:
        #         if block.name == self.UNWIND_INFO:
        #             return True

        return False

    def get_data_type(self) -> DataType:
        structure = StructureDataType("unwindStruct", 0)
        structure.add(FloatDataType(), "a", "this is a float")
        structure.add(DWordDataType(), "b", "this is a dword")
        structure.add(DoubleDataType(), "c", "this is a double")
        return structure
