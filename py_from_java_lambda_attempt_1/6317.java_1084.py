Here is the equivalent Python code:

```Python
import unittest
from ghidra_app_plugin.core.compositeeditor import *
from ghidra.program.model.data import *

class UnionEditorDnDTTest(unittest.TestCase):

    def testDragNDropAddDifferentTypes(self):
        init(emptyUnion, pgmRootCat, False)
        dt = model.getOriginalDataTypeManager().getDataType("/byte")
        self.assertIsNotNone(dt)

        assertEquals(0, model.getNumComponents())

        addAtPoint(dt, 0, 0)
        assertEquals(1, model.getNumComponents())
        assertTrue(getDataType(0).isEquivalent(dt))
        assertEquals(dt.getLength(), model.getComponent(0).getLength())

        dt = model.getOriginalDataTypeManager().getDataType("/double")
        self.assertIsNotNone(dt)

        addAtPoint(dt, 1, 0)
        assertEquals(2, model.getNumComponents())
        assertTrue(getDataType(0).isEquivalent(dt))
        assertEquals(dt.getLength(), model.getComponent(0).getLength())

        dt3 = new Pointer32DataType()
        self.assertIsNotNone(dt3)

        addAtPoint(dt3, 2, 0)
        assertEquals(3, model.getNumComponents())
        assertTrue(getDataType(0).isEquivalent(dt3))
        assertEquals(4, model.getComponent(0).getLength())

        dt4 = model.getOriginalDataTypeManager().getDataType("/string")
        self.assertIsNotNone(dt4)

        addAtPoint(dt4, 2, 0)
        dialog = waitForDialogComponent(NumberInputDialog.class)
        self.assertIsNotNone(dialog)
        okInput(dialog, 25)
        dialog = None
        waitUntilDialogProviderGone(NumberInputDialog.class, 2000)
        assertEquals(3, model.getNumComponents())
        assertTrue(getDataType(2).isEquivalent(dt4))
        assertEquals(25, model.getComponent(2).getLength())

    def testDragNDropInsertDifferentTypes(self):
        init(complexUnion, pgmTestCat, False)

        dt = model.getOriginalDataTypeManager().getDataType("/word")
        self.assertIsNotNone(dt)

        assertEquals("float", getDataType(4).getDisplayName())
        addAtPoint(dt, 0, 3)
        assertEquals(model.getNumComponents(), 5)
        assertEquals("qword", getDataType(4).getDisplayName())
        assertTrue(getDataType(4).isEquivalent(dt))
        assertEquals(dt.getLength(), model.getComponent(4).getLength())

    def testDragNDropOnPointer(self):
        init(complexUnion, pgmTestCat, False)

        dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer8")
        self.assertIsNotNone(dt)

        addAtPoint(dt, 2, 3)
        assertEquals(model.getNumComponents(), 5)
        assertEquals("pointer8", getDataType(4).getDisplayName())
        assertTrue(getDataType(4) instanceof Pointer)
        assertEquals(1, model.getComponent(4).getLength())

    def testDragNDropPointerOnByte(self):
        init(simpleUnion, pgmBbCat, False)

        dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer")
        self.assertIsNotNone(dt)

        addAtPoint(dt, 0, 3)
        assertEquals(model.getNumComponents(), 1)
        assertEquals("pointer", getDataType(0).getDisplayName())
        assertTrue(getDataType(0) instanceof Pointer)
        assertEquals(4, model.getComponent(0).getLength())

    def testDragNDropInsertPointer(self):
        init(simpleUnion, pgmBbCat, False)

        dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer")
        self.assertIsNotNone(dt)

        addAtPoint(dt, 1, 3)
        assertEquals(model.getNumComponents(), 2)
        assertEquals("pointer", getDataType(1).getDisplayName())
        assertTrue(getDataType(1) instanceof Pointer)
        assertEquals(4, model.getComponent(1).getLength())

    def testDragNDropInsertSizedPointer(self):
        init(simpleUnion, pgmBbCat, False)

        dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer32")
        self.assertIsNotNone(dt)

        addAtPoint(dt, 1, 3)
        assertEquals(model.getNumComponents(), 2)
        assertEquals("pointer32", getDataType(1).getDisplayName())
        assertTrue(getDataType(1) instanceof Pointer)
        assertEquals(4, model.getComponent(1).getLength())

    def testDragNDropUnionOnSelf(self):
        init(complexUnion, pgmTestCat, False)

        addAtPoint(complexUnion, 5, 0)
        assertEquals(model.getNumComponents(), 6)
        assertEquals("Data type \"complexUnion\" can't contain itself.", model.getStatus())

if __name__ == '__main__':
    unittest.main()
```