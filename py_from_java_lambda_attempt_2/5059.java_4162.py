Here is the translation of the Java code into Python:

```Python
import logging

class ControlFlowGuard:
    GuardCFFunctionTableName = "GuardCFFunctionTable"
    GuardCFAddressTakenIatTableName = "GuardCFAddressTakenIatTable"
    GuardCfgTableEntryName = "GuardCfgTableEntry"

    def markup(lcd, program, log):
        is64bit = lcd.getOptionalHeader().is64bit()
        space = program.getAddressFactory().getDefaultAddressSpace()
        mem = program.getMemory()
        symbol_table = program.getSymbolTable()

        # ControlFlowGuard
        if lcd.getCfgCheckFunctionPointer() != 0:
            markup_cfg_check_function(lcd, program, is64bit, space, mem, symbol_table)

        if lcd.getCfgDispatchFunctionPointer() != 0:
            markup_cfg_dispatch_function(lcd, program, is64bit, space, mem, symbol_table)

        if lcd.getCfgFunctionTablePointer() != 0 and lcd.getFuncCount() > 0:
            markup_cfg_function_table(lcd, program, log)
            create_cfg_functions(program, table_data, log)

        # ReturnFlowGuard
        if lcd.getRfgFailureRoutine() != 0:
            markup_rfg_failure_routine(lcd, program, space, symbol_table)

        if lcd.getRfgDefaultFailureRoutineFunctionPointer() != 0:
            markup_rfg_default_failure_routine(lcd, program, is64bit, space, mem, symbol_table)

        if lcd.getRfgVerifyStackPointerFunctionPointer() != 0:
            markup_rfg_default_stack_pointer_function(lcd, program, is64bit, space, mem, symbol_table)


    def markup_cfg_check_function(lcd, program, is64bit, space, mem, symbol_table):
        try:
            function_addr = space.getAddress(lcd.getCfgCheckFunctionPointer())
            if not symbol_table.createLabel(function_addr, "_guard_ check_icall", SourceType.IMPORTED):
                logging.warning("Unable to label ControlFlowGuard check function.")
        except (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException) as e:
            logging.warning(f"Unable to label ControlFlowGuard check function. {e}")


    def markup_cfg_dispatch_function(lcd, program, is64bit, space, mem, symbol_table):
        try:
            function_addr = space.getAddress(lcd.getCfgDispatchFunctionPointer())
            if not symbol_table.createLabel(function_addr, "_guard_ dispatch_icall", SourceType.IMPORTED):
                logging.warning("Unable to label ControlFlowGuard dispatch function.")
        except (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException) as e:
            logging.warning(f"Unable to label ControlFlowGuard dispatch function. {e}")


    def markup_cfg_function_table(lcd, program, log):
        table_pointer = lcd.getCfgFunctionTablePointer()
        func_count = lcd.getFuncCount()

        if table_pointer == 0 or func_count <= 0:
            return

        try:
            table_addr = space.getAddress(table_pointer)
            symbol_table.createLabel(table_addr, GuardCFFunctionTableName, SourceType.IMPORTED)

            # Each table entry is an RVA (32-bit image base offset), followed by 'n' extra bytes
            guard_flags = lcd.getGuardFlags()
            n = (guard_flags & 0xf0000000) >> 28

            # Pre-define base data types used to define table entry data type
            ibo_32 = ImageBaseOffset32DataType()
            byte_type = ByteDataType.dataType

            category_path = CategoryPath(CategoryPath.ROOT, "CFG")
            structure_data_type = StructureDataType(category_path, GuardCfgTableEntryName)
            if not structure_data_type:
                structure_data_type = StructureDataType(category_path, GuardCfgTableEntryName, 0)

        except (AddressOutOfBoundsException | InvalidInputException) as e:
            logging.warning(f"Unable to label ControlFlowGuard function table. {e}")


    def create_cfg_functions(program, table_data, log):
        if not table_data or not isinstance(table_data, list):
            return

        for target in get_function_addresses_from_table(program, table_data):
            AbstractProgramLoader.mark_as_function(program, None, target)
            logging.info(f"Marked function at {target}")


    def markup_rfg_failure_routine(lcd, program, space, symbol_table):
        try:
            routine_addr = space.getAddress(lcd.getRfgFailureRoutine())
            if not symbol_table.createLabel(routine_addr, "_guard_ss_verify_failure", SourceType.IMPORTED):
                logging.warning("Unable to label ReturnFlowGuard failure routine.")
        except (AddressOutOfBoundsException | InvalidInputException) as e:
            logging.warning(f"Unable to label ReturnFlowGuard failure routine. {e}")


    def markup_rfg_default_stack_pointer_function(lcd, program, is64bit, space, mem, symbol_table):
        try:
            function_addr = space.getAddress(lcd.getRfgVerifyStackPointerFunctionPointer())
            if not symbol_table.createLabel(function_addr, "_guard_ss_verify_sp_default", SourceType.IMPORTED):
                logging.warning("Unable to label ReturnFlowGuard verify stack pointer function.")
        except (MemoryAccessException | AddressOutOfBoundsException | InvalidInputException) as e:
            logging.warning(f"Unable to label ReturnFlowGuard verify stack pointer function. {e}")


    def get_function_addresses_from_table(program, table_data):
        if not isinstance(table_data, list):
            return []

        addresses = []
        for i in range(len(table_data)):
            entry = table_data[i]
            value = entry.get_value()
            if isinstance(value, Address):
                addresses.append(value)

        return addresses
```

Please note that Python does not have direct equivalents to Java's `try-catch` blocks or exception handling. Instead, you can use the built-in `except` block to catch and handle exceptions.