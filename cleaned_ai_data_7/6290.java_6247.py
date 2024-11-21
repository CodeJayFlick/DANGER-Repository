import unittest
from ghidra.app.plugin.core.compositeeditor import *
from docking.widgets.dialogs.numberinputdialog import NumberInputDialog
from org.junit.assert import *

class StructureEditorLockedActions2Test(unittest.TestCase):

    def testCycleGroupByteSomeRoom(self):
        init(complexStructure, pgmTestCat)
        runSwing(lambda: getModel().clearComponents([2, 3])) # clear 6 bytes
        dt8 = getDataType(8)
        len_dt8 = getLength(8)
        num_components = getModel().getNumComponents()
        length = getModel().getLength()

        setSelection([1])
        action = getCycleGroup(ByteDataType())
        invoke(action)
        self.assertEqual(num_components - 1, getModel().getNumComponents())
        self.assertEqual(length, getModel().getLength())
        self.assertTrue(getDataType(1).isEquivalent(WordDataType()))
        self.assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT))
        self.assertTrue(getDataType(6).isEquivalent(DataType.DEFAULT))
        checkSelection([1])
        self.assertEqual(2, getLength(1))
        self.assertEqual(length - 5, len_dt8)
        self.assertEqual(dt8, getDataType(7))

    def testCycleGroupFloatLotsOfRoom(self):
        init(complexStructure, pgmTestCat)
        runSwing(lambda: getModel().clearComponents([2, 3, 4])) # clear 14 bytes
        dt16 = getDataType(16)
        len_dt16 = getLength(16)
        num_components = getModel().getNumComponents()
        length = getModel().getLength()

        setSelection([1])
        action = getCycleGroup(FloatDataType())
        invoke(action)
        self.assertEqual(num_components - 3, getModel().getNumComponents())
        self.assertEqual(length, getModel().getLength())
        self.assertTrue(getDataType(1).isEquivalent(FloatDataType()))
        self.assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT))
        self.assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT))
        checkSelection([1])
        self.assertEqual(4, getLength(1))
        self.assertEqual(length - 13, len_dt16)
        self.assertEqual(dt16, getDataType(13))

    def testCycleGroupFloatNoRoom(self):
        init(complexStructure, pgmTestCat)

        dt1 = getDataType(1)
        num_components = getModel().getNumComponents()
        length = getModel().getLength()

        setSelection([0])
        action = getCycleGroup(FloatDataType())
        invoke(action)
        self.assertTrue("", getModel().getStatus())
        self.assertEqual(num_components, getModel().getNumComponents())
        self.assertEqual(length, getModel().getLength())
        self.assertTrue(getDataType(0).isEquivalent(DataType.DEFAULT))
        checkSelection([0])
        self.assertEqual(1, getLength(1))
        self.assertEqual(dt1, getDataType(1))

    def testCycleGroupOnMultiLine(self):
        init(simpleStructure, pgmBbCat)

        dt0 = getDataType(0)
        dt1 = getDataType(1)
        dt2 = getDataType(2)
        dt3 = getDataType(3)
        num_components = getModel().getNumComponents()

        setSelection([1, 2])
        action = getCycleGroup(CharDataType())
        invoke(action)

    def testDuplicateAction(self):
        init(complexStructure, pgmTestCat)
        model.clearComponent(3)
        model.setComponentName(2, "comp2")
        model.setComponentComment(2, "comment 2")

        num_components = getModel().getNumComponents()
        length = getModel().getLength()

        setSelection([2])
        dt2 = getDataType(2)
        dt3 = getDataType(3)

        invoke(duplicateAction)
        self.assertEqual(num_components - 1, getModel().getNumComponents())
        checkSelection([2])
        self.assertEqual(getDataType(2), dt2)
        self.assertEqual(getDataType(3), dt2)
        self.assertEqual(dt3, getDataType(4))
        self.assertEqual("comp2", getFieldname(2))
        self.assertEqual("comment 2", getComment(2))

    def testDuplicateMultipleAction(self):
        init(complexStructure, pgmTestCat)
        model.clearComponent(3)
        model.setComponentName(2, "comp2")
        model.setComponentComment(2, "comment 2")

        num_components = getModel().getNumComponents()

        setSelection([2])
        dt2 = getDataType(2)
        dt7 = getDataType(7)

        invoke(duplicateMultipleAction, False)
        dialog = waitForDialog("Specify the Structure's Name")
        assertNotNull(dialog)
        badInput(dialog, 3)
        dialog = getDialogComponent()
        okInput(dialog, 2)
        dialog = None
        waitUntilDialogProviderGone(NumberInputDialog.class, 2000)

    def testExistingAlignedDtEditInternalStructureOnSelectionDefaultName(self):
        init(simpleStructure, pgmBbCat)

        assertEquals(7, getModel().getNumComponents())

        setSelection([1, 2, 3])
        original_dt1 = getDataType(1)
        original_dt2 = getDataType(2)
        original_dt3 = getDataType(3)
        original_dt4 = getDataType(4)

        invoke(createInternalStructureAction, False)

    def testExistingDtEditInternalStructureOnSelectionCancelOnName(self):
        init(simpleStructure, pgmBbCat)

        assertEquals(8, getModel().getNumComponents())

        setSelection([1, 2, 3])
        original_dt1 = getDataType(1)
        original_dt2 = getDataType(2)
        original_dt3 = getDataType(3)
        original_dt4 = getDataType(4)

        invoke(createInternalStructureAction, False)

    def testExistingDtEditInternalStructureOnSelectionDefaultName(self):
        init(simpleStructure, pgmBbCat)

        assertEquals(8, getModel().getNumComponents())

        setSelection([1, 2, 3])
        original_dt1 = getDataType(1)
        original_dt2 = getDataType(2)
        original_dt3 = getDataType(3)
        original_dt4 = getDataType(4)

        invoke(createInternalStructureAction, False)


if __name__ == '__main__':
    unittest.main()
