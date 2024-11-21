Here is the translation of the given Java code into equivalent Python:

```Python
import ghidra_app_script as GAS
from ghidra_program_model import *
from ghidra_listing import *

class MakeFunctionsInlineVoidScript:
    def run(self):
        cnt = 0
        if current_selection and not current_selection.empty():
            fn_iter = current_program.get_function_manager().get_functions(current_selection, True)
            while fn_iter.has_next():
                self.update_function(fn_iter.next())
                cnt += 1
        elif current_location:
            func = current_program.get_function_manager().get_function_containing(current_location.get_address())
            if func:
                self.update_function(func)
                cnt += 1
        GAS.set_tool_status_message(f"{cnt} function(s) set as inline void", False)

    def update_function(self, func):
        try:
            func.set_inline(True)
            func.set_return_type(DataType.void(), SourceType.USER_DEFINED)
        except Exception as e:
            print(e)

MakeFunctionsInlineVoidScript().run()
```

Please note that this is a direct translation of the given Java code into Python and may not be perfect or idiomatic Python.