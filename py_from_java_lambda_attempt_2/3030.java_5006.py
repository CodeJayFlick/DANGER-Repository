Here is the translation of the given Java code into Python:

```Python
import ghidra_script as script
from ghidra_framework import *
from java.util import Iterator

class FindDataTypeScript(script.GhidraScript):
    def run(self):
        manager = self.get_data_type_manager_by_name("generic_ C_lib")
        if manager is None:
            print("Archive must not be open in the Data Type Manager")
            return
        
        specific_data_type = manager.get_data_type("/complex.h/defines/define__COMPLEX_H")
        print(f"Data type: {specific_data_type}")

        # without the category path
        print("Now searching for any matching type in generic_ C_lib:")
        all_data_types = manager.get_all_data_types()
        while all_data_types.hasNext():
            data_type = all_data_types.next()
            data_type_name = data_type.name
            if "COMPLEX" not in data_type_name:
                continue
            print(f"\tFound match: {data_type}")
        
        print("Done searching")

        # In the built-in DTM		
        manager = self.get_data_type_manager_by_name("BuiltInTypes")
        print("Now searching for any matching type in BuiltInTypes:")
        all_data_types = manager.get_all_data_types()
        while all_data_types.hasNext():
            data_type = all_data_types.next()
            data_type_name = data_type.name
            if "sdword" not in data_type_name:
                continue
            print(f"\tFound match: {data_type}")
        
        print("Done searching")

    def get_data_type_manager_by_name(self, name):
        tool = self.state.get_tool()
        service = tool.get_service(DataTypeManagerService)
        managers = service.get_data_type_managers()
        for manager in managers:
            if manager.name == name:
                return manager
        return None

FindDataTypeScript().run()
```

Please note that this code is not tested and may require adjustments based on the actual usage of `ghidra_script`, `GhidraScript` class, etc.