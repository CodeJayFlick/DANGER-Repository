Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra_framework import *
from ghidra_program_model_address import *

class FunctionNameMarkupItemTest(unittest.TestCase):
    def testFindAndApplyMarkupItem_ReplaceDefault_WithDefaultDestinationName(self):
        sourceAddress = addr("0x01002cf5", self.sourceProgram)
        destinationAddress = addr("0x01003f9e", self.destinationProgram)

        sourceFunction = self.sourceProgram.getFunctionManager().getFunctionAt(sourceAddress)
        destinationFunction = self.destinationProgram.getFunctionManager().getFunctionAt(destinationAddress)

        validator = FunctionNameValidator(
            sourceFunction, 
            destinationFunction, 
            sourceFunction.getName() + getNonDynamicName(), 
            destinationFunction.getName(), 
            FunctionNameChoices.REPLACE_DEFAULT_ONLY
        )
        doTestFindAndApplyMarkupItem(validator)

    def testApplyFunctionName_ReplaceDefault_WithNewName(self):
        # ... similar tests ...

class FunctionNameValidator:
    def __init__(self, source_function, destination_function, source_name, destination_name, function_name_choice):
        self.source_function = source_function
        self.destination_function = destination_function
        self.destination_name = destination_name

    @property
    def get_destination_match_address(self):
        return self.destination_function.get_entry_point()

class Function:
    pass

def create_external_function(program, path):
    # ... similar code ...

if __name__ == "__main__":
    unittest.main()
```

Note: The above Python translation is based on the assumption that you are using a framework like `ghidra` which provides classes and methods for working with Ghidra.