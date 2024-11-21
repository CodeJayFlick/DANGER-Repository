class PdbDataTypeParser:
    NO_TYPE = "<NoType>"
    NO_ETYPE_DATATYPE = WrappedDataType(TypedefDataType(NO_TYPE, Undefined1DataType.data_type), False, True)

    def __init__(self, program_data_type_mgr: 'ghidra.program.database.data.DataTypeManager', 
                 service: 'ghidra.app.services.DataTypeManagerService', monitor: 'ghidra.util.task.TaskMonitor'):
        self.program_data_type_mgr = program_data_type_mgr
        self.service = service
        self.monitor = monitor
        self.create_mandatory_data_types()

    def create_mandatory_data_types(self):
        self.cache_primitive_datatype(TypedefDataType("wchar", WideCharDataType.data_type))
        self.cache_primitive_datatype(TypedefDataType("__int8",
            AbstractIntegerDataType.get_signed_datatype(1, self.program_data_type_mgr)))
        self.cache_primitive_datatype(TypedefDataType("__uint8",
            AbstractIntegerDataType.get_unsigned_datatype(1, self.program_data_type_mgr)))

    def get_program_data_type_manager(self):
        return self.program_data_type_mgr

    def flush_data_type_cache(self) -> None:
        for dt in list(self.data_type_cache.values()):
            try:
                if monitor.is_cancelled():
                    raise CancelledException
                self.program_data_type_mgr.add_datatypes([dt], 
                    DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER, self.monitor)
            except CancelledException as e:
                raise

    def clear(self):
        self.data_type_cache = {}

    def get_cached_data_type(self, key: str) -> 'ghidra.program.database.data.DataType':
        return self.data_type_cache.get(key)

    def cache_datatype(self, key: str, dt: 'ghidra.program.database.data.DataType'):
        self.data_type_cache[key] = dt

    def find_base_data_type(self, datatype_name: str, monitor) -> 'ghidra.program.database.data.DataType':
        if datatype_name in self.data_type_cache:
            return self.get_cached_datatype(datatype_name)
        
        built_in_dtm = BuiltInDataTypeManager.get_datatype_manager()
        dt = built_in_dtm.get_datatype(DataTypePath(ROOT, datatype_name))
        if dt is None:
            dt = find_data_type_in_archives(datatype_name, monitor)

        return dt

    def find_data_type(self, datatype: str) -> 'ghidra.program.database.data.DataType':
        datatype = datatype.strip()
        
        if datatype == self.NO_TYPE:
            return self.NO_ETYPE_DATATYPE
        
        base_pointer_depth = 0
        while datatype.endswith("*"):
            base_pointer_depth += 1
            datatype = datatype[:-1].strip()

        is_zero_length_array = False
        array_dimensions = None
        if datatype.endswith("]"):
            array_dimensions = []
            datatype = parse_array_dimensions(datatype, array_dimensions)
            if datatype is None:
                return None
            is_zero_length_array = (array_dimensions[-1] == 0)

        pointer_depth = 0
        dt = find_base_data_type(datatype, self.monitor)
        
        while base_pointer_depth > 0 or pointer_depth > 0:
            dt = create_pointer(dt)
            
            if array_dimensions and not is_zero_length_array:
                dt = create_array(dt, array_dimensions)

            if pointer_depth > 0:
                dt = create_pointer(dt)
                
            pointer_depth -= 1

        return WrappedDataType(dt, is_zero_length_array, False)

    def parse_array_dimensions(self, datatype: str) -> str:
        while True:
            lBracketPos = datatype.find('[')
            rBracketPos = datatype.rfind(']')
            
            if lBracketPos < 0 or rBracketPos < 0:
                return None
            
            dimension
            try:
                dimension = int(datatype[lBracketPos+1:rBracketPos])
                if dimension < 0:
                    return None
                
                array_dimensions.append(dimension)
                
                datatype = datatype[:lBracketPos].strip()
            
    def create_pointer(self, dt: 'ghidra.program.database.data.DataType') -> 'ghidra.program.database.data.DataType':
        return PointerDataType.get_pointer(dt, self.program_data_type_mgr)

    def create_array(self, dt: 'ghidra.program.database.data.DataType', array_dimensions) -> 'ghidra.program.database.data.DataType':
        dimension_count = len(array_dimensions)
        
        if array_dimensions[-1] == 0:
            --dimension_count
            
        for i in range(dimension_count):
            dimension = array_dimensions[i]
            
            dt = ArrayDataType(dt, dimension, dt.get_length(), self.program_data_type_mgr)

    def set_missing_bit_offset_error(self) -> None:
        self.bitfield_has_missing_bit_offset = True

    def has_missing_bit_offset_error(self) -> bool:
        return self.bitfield_has_missing_bit_offset
