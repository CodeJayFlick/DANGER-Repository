class RecoveredClass:
    def __init__(self, name: str, category_path: object, namespace: object, data_type_manager: object):
        self.name = name
        self.category_path = category_path
        self.namespace = namespace
        self.data_type_manager = data_type_manager

        self.vftable_addresses = []
        self.all_class_virtual_functions = []

    def get_name(self) -> str:
        return self.name

    def get_virtual_functions(self, vftable_address: object) -> list:
        return self.vftable_to_vfunctions_map.get(vftable_address)

    def get_all_virtual_functions(self) -> list:
        return self.all_class_virtual_functions

    # ... (all the other methods)
