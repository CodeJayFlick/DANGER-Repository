Here is the equivalent Python script:

```Python
import ghidra


class ChangeDataSettingsScript:
    def run(self):
        data = self.get_data_at(current_address)
        if data is None:
            print("No data exists.")
            return
        
        component_count = data.num_components()
        if component_count == 0:
            print("Data does not have any sub-components.")
            return

        for i in range(component_count):
            component = data.get_component(i)
            if component is None:
                break
            
            settings_definitions = component.data_type.settings_definitions
            for setting_definition in settings_definitions:
                if isinstance(setting_definition, ghidra.docking.settings.FormatSettingsDefinition):
                    format_setting_definition = setting_definition
                    format_setting_definition.set_choice(component, ghidra.docking.settings.FormatSettingsDefinition.DECIMAL)


# This is the entry point of your script. It will be called when you run this script in Ghidra.
if __name__ == '__main__':
    ChangeDataSettingsScript().run()
```

Please note that Python does not support direct translation from Java code to Python, as both languages have different syntax and semantics. This is a manual translation of the provided Java code into equivalent Python code.