class FunctionRowObjectToAddressTableRowMapper:
    def map(self, row_object: 'VTFunctionRowObject', data: 'Program', service_provider: 'ServiceProvider') -> Address:
        function_manager = data.get_function_manager()
        info = row_object.get_info()
        function = function_manager.get_function(info.get_function_id())
        return function.get_entry_point()

class VTFunctionRowObject:
    def get_info(self) -> 'FunctionAssociationInfo':
        pass

class FunctionAssociationInfo:
    def get_function_id(self) -> int:
        pass
