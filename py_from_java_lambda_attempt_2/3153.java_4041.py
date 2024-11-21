Here is the translation of the given Java code into Python:

```Python
class CreateDataInStructureCmd:
    def __init__(self, addr, component_path, new_data_type):
        self.addr = addr
        self.component_path = component_path
        self.new_data_type = new_data_type

    def apply_to(self, obj):
        program = Program(obj)
        data = program.get_listing().get_defined_data_containing(addr)
        if not data:
            return False
        
        parent_data_type = data.get_component(component_path).get_parent().get_base_data_type()
        
        if not isinstance(parent_data_type, Composite):
            return False

        new_data_type = DataUtilities.reconcile_applied_data_type(data.get_component(component_path).get_data_type(), self.new_data_type)
        
        if new_data_type == DataType.DEFAULT:
            data.get_component(component_path).clear()
        else:
            dti = DataTypeInstance(new_data_type, -1)
            parent_data_type.replace(component_path[0], dti.data_type, dti.length)

    def get_status_msg(self):
        return self.msg

    def get_name(self):
        return f"Create {self.new_data_type.get_display_name()} component"
```

Note: This translation assumes that the Java code is part of a larger program and does not include all necessary imports or classes.