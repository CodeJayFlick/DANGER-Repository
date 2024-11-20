Here is a translation of the provided Java code into equivalent Python:

```Python
import ghidra_app as app
from ghidra_framework import *
from ghidra_program_model_data import DataUtilities
from ghidra_string_translation_service import StringTranslationService

class SampleStringTranslationPlugin(StringTranslationService):
    def __init__(self, tool: 'ghidra_tool'):
        super().__init__()

    def get_translation_service_name(self) -> str:
        return "Sample Translation Service"

    def translate(self, program: Program, data_locations: List[ProgramLocation]):
        for prog_loc in data_locations:
            data = DataUtilities.get_data_at_location(prog_loc)
            if isinstance(data, StringDataInstance):
                s = data.string_value
                translated_value = s.replace("([ _,;:.])", r"\1YEEHAW!\1")
                TRANSLATION.set_translated_value(data, translated_value)

class ghidra_examples:
    pass

if __name__ == "__main__":
    # Initialize the Ghidra application and plugin
    app.init()
    tool = app.get_plugin_tool()

    # Create an instance of our translation service plugin
    sample_translation_service = SampleStringTranslationPlugin(tool)
```

Please note that this is a direct translation from Java to Python, without considering any specific requirements or limitations.