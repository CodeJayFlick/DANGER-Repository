class AbstractTypeDefAction:
    def __init__(self, name, plugin):
        self.plugin = plugin
        super().__init__(name)

    def create_typedef(self, data_type_manager: 'DataTypeManager', 
                       data_type: 'DataType', category_path: str, context: dict,
                       parent_node: object, type_def_name: str) -> 'DataType':
        
        if not isinstance(data_type_manager, (object)):
            data_type_manager = self.plugin.get_program_data_type_manager()
            
        if isinstance(data_type, FunctionDefinition):
            data_type = PointerDataType.get_pointer(data_type, data_type_manager)
            
        component_provider = context.get('component_provider')
        comp = None
        if component_provider:
            comp = component_provider.get_component()

        if not self.plugin.is_valid_typedef_base_type(comp, data_type):
            return None

        return create_new_data_type(None, data_type, category_path, 
                                    data_type_manager, type_def_name)

    def create_new_data_type(self, parent_component: object, data_type: 'DataType', 
                             category_path: str, data_type_manager: 'DataTypeManager',
                             name: str) -> 'DataType':
        newdt = None
        transaction_id = data_type_manager.start_transaction("Create Typedef")
        
        try:
            typedef = TypedefDataType(category_path, name, data_type)
            newdt = data_type_manager.add_data_type(typedef, self.plugin.get_conflict_handler())
            
        finally:
            data_type_manager.end_transaction(transaction_id, True)

        return newdt
