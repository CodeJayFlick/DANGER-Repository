Here is the equivalent Python code:

```Python
import unittest
from ghidra.app.plugin.core.compositeeditor import *
from docking.widgets.dialogs.numberinputdialog import NumberInputDialog
from ghidra.program.model.data import Array, DataType


class UnionEditorActions3Test(unittest.TestCase):

    def testArrayOnArray(self):
        self.init(complexUnion, pgmTestCat, False)
        dialog = None
        num_components = model.getNumComponents()
        
        self.setSelection([11])
        dt_11 = getDataType(11)

        # Make array of 2 arrays
        self.invoke(arrayAction, False)
        dialog = NumberInputDialog(waitForDialogComponent())
        self.assertIsNotNone(dialog)
        okInput(dialog, 2)
        dialog = None
        waitUntilDialogProviderGone(NumberInputDialog(), 2000)
        
        self.assertEqual(num_components, model.getNumComponents())
        self.assertEqual("string[2][5]", getDataType(11).getDisplayName())
        self.assertTrue(getDataType(11) == dt_11)
        self.assertEqual(90, getDataType(11).getLength())
        self.assertEqual(90, model.getComponent(11).getLength())

    def testArrayOnFixedDt(self):
        self.init(simpleUnion, pgmBbCat, False)
        dialog = None
        num_components = model.getNumComponents()

        self.setSelection([3])
        dt_3 = getDataType(3)

        # Make array of 5 quadwords
        self.invoke(arrayAction, False)
        dialog = NumberInputDialog(waitForDialogComponent())
        self.assertIsNotNone(dialog)
        okInput(dialog, 5)
        dialog = None
        waitUntilDialogProviderGone(NumberInputDialog(), 2000)

        self.assertEqual(num_components, model.getNumComponents())
        self.assertTrue(getDataType(3) == dt_3)
        self.assertEqual(40, getDataType(3).getLength())
        self.assertEqual(40, model.getComponent(3).getLength())

if __name__ == '__main__':
    unittest.main()
```

Note: This code assumes that the following functions are defined elsewhere in your Python script:

- `init()`
- `setSelection()`
- `invoke()`
- `waitForDialogComponent()`
- `okInput()`
- `waitUntilDialogProviderGone()`