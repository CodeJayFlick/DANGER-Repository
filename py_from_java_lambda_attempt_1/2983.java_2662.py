Here is the equivalent Python script:

```Python
import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.data import DataTypeManager, AllowedDataTypes
from ghidra.util.exception import InvalidInputException

class ChooseDataTypeScript(GhidraScript):
    def run(self):
        tool = self.state.getTool()
        dtm = self.currentProgram.getDataTypeManager()
        selection_dialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
        try:
            tool.showDialog(selection_dialog)
            chosen_data_type = selection_dialog.getUserChosenDataType()
            if chosen_data_type is not None:
                print(f"Chosen data type: {chosen_data_type}")
        except InvalidInputException as e:
            print(f"Error occurred: {e}")

if __name__ == "__main__":
    ChooseDataTypeScript().run()
```

Please note that this Python script uses the `ghidra` library, which is specific to Ghidra. The code you provided seems to be a part of a larger program or framework (Ghidra), and it's not possible to translate it directly into pure Python without any dependencies on external libraries.