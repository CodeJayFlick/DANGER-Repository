Here is the translation of the Java code into Python:

```Python
import unittest
from ghidra.app.plugin.core.compositeeditor import *
from ghidra.program.model.data import *
from ghidra.util.exception import DuplicateNameException, UsrException
from ghidra.util.task import TaskMonitor

class UnionEditorNotifiedTest(unittest.TestCase):

    def setUp(self):
        self.init = None
        self.cleanup = None

    @classmethod
    def setUpClass(cls):
        cls.init = init
        cls.cleanup = cleanup

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'cleanup'):
            cls.cleanup()

    def testCategoryAdded(self):
        # Nothing to test here.
        pass

    def testComponentDtCategoryMoved(self):
        try:
            self.init(complexUnion, pgmTestCat, False)
            assertEquals("/aa/bb", getDataType(20).getCategoryPath().getPath())
            pgmBbCat.moveCategory(pgmRootCat.getCategoryPath(), TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals("/testCat/aa", getDataType(20).getCategoryPath().getPath())
        finally:
            self.cleanup()

    def testEditedDtCategoryMoved(self):
        try:
            self.init(simpleUnion, pgmBbCat, False)
            assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath())
            pgmAaCat.moveCategory(complexUnion, TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals(pgmAaCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath())
        finally:
            self.cleanup()

    def testComponentDtCategoryRemoved(self):
        try:
            self.init(complexUnion, pgmTestCat, False)
            assertEquals(21, model.getNumComponents())
            complexUnion.getDataTypeManager().remove(simpleStructure, TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals(15, model.getNumComponents())
        finally:
            self.cleanup()

    def testEditedDtCategoryRemoved(self):
        try:
            self.init(complexUnion, pgmTestCat, False)
            int num = model.getNumComponents()
            DataType origCopy = complexUnion.clone(None)

            complexUnion.getDataTypeManager().remove(refUnion, TaskMonitor.DUMMY)  # remove refUnion
            waitForSwing()

            # refUnion* gets removed (1 component)
            num -= 1
            assertEquals(num, model.getNumComponents())
            assertTrue(origCopy.isEquivalent(model.viewComposite))
        finally:
            self.cleanup()

    def testComponentDtCategoryRenamed(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            assertTrue(simpleStructure.isEquivalent(getDataType(3)))
            assertEquals(simpleStructure.getPathName(), getDataType(3).getPathName())
            simpleStructure.setName("NewSimpleUnion")
            waitForSwing()
            assertTrue(simpleStructure.isEquivalent(getDataType(3)))
            assertEquals(simpleStructure.getPathName(), getDataType(3).getPathName())
        finally:
            self.cleanup()

    def testEditedDtCategoryRenamed(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath())
            simpleStructure.setName("NewSimpleUnion")
            waitForSwing()
            assertEquals(pgmAaCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath())
        finally:
            self.cleanup()

    def testComponentDataTypeChanged(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            int len12 = dt12.getLength()
            int len15 = dt15.getLength()
            int len20 = dt20.getLength()  # struct
            simpleStructure.add(new DWordDataType())
            waitForSwing()

            assertEquals(len12 + (3 * 4), getDataType(12).getLength())
            assertEquals(len15 + 4, getDataType(15).getLength())
            assertEquals(len20 + 4, getDataType(20).getLength())

        finally:
            self.cleanup()

    def testEditedDataTypeChanged(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            runSwing(lambda: model.insert(model.getNumComponents(), new ByteDataType(), 1))
            simpleStructure.add(new CharDataType())
            waitForSwing()
            assertEquals(((Union) origCopy).getNumComponents(), model.getNumComponents())

        finally:
            self.cleanup()

    def testComponentDataTypeMoved(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            assertEquals(21, model.getNumComponents())
            simpleStructure.moveCategory(pgmAaCat.getCategoryPath(), TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals(21, model.getNumComponents())

        finally:
            self.cleanup()

    def testEditedDataTypeMoved(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath())
            simpleStructure.moveCategory(pgmAaCat.getCategoryPath(), TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals(pgmAaCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath())

        finally:
            self.cleanup()

    def testComponentDataTypeRemoved(self):
        try:
            self.init(complexUnion, pgmTestCat, False)

            int num = model.getNumComponents()
            simpleStructure.getDataTypeManager().remove(simpleStructure, TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals(15, model.getNumComponents())

        finally:
            self.cleanup()

    def testOnlyComponentDataTypeRemoved(self):
        try:
            self.init(emptyUnion, pgmTestCat, False)

            runSwing(lambda: model.add(simpleUnion))
            simpleStructure.getDataTypeManager().remove(simpleStructure, TaskMonitor.DUMMY)
            waitForSwing()
            assertEquals(0, model.getNumComponents())

        finally:
            self.cleanup()

    def testEditedDataTypeReplacedYes(self):
        try:
            window = None
            runSwing(lambda: model.insert(model.getNumComponents(), new ByteDataType(), 1))
            unionNewComplexUnion = Union(new CategoryPath("/aa/aa"), complexUnion.getName())
            unionNewComplexUnion.add(new PointerDataType(), 8)
            unionNewComplexUnion.add(new CharDataType(), 1)

            programDTM.replaceDataType(complexUnion, unionNewComplexUnion, True)
            waitForSwing()
            dataTypeOrigCopy = unionNewComplexUnion.clone(None)

            window = env.waitForWindow("Reload Union Editor?", 1000)
            assertNotNone(window)
            pressButtonByText(window, "Yes")
            window.dispose()

        finally:
            if hasattr(self, 'window'):
                self.window.dispose()
            self.cleanup()

    def testEditedDataTypeReplacedNo(self):
        try:
            window = None
            runSwing(lambda: model.insert(model.getNumComponents(), new ByteDataType(), 1))
            unionNewComplexUnion = Union(new CategoryPath("/aa/aa"), complexUnion.getName())
            unionNewComplexUnion.add(new PointerDataType(), 8)
            unionNewComplexUnion.add(new CharDataType(), 1)

            programDTM.replaceDataType(complexUnion, unionNewComplexUnion, True)
            waitForSwing()

            window = env.waitForWindow("Reload Union Editor?", 1000)
            assertNotNone(window)
            pressButtonByText(window, "No")
            window.dispose()

        finally:
            if hasattr(self, 'window'):
                self.window.dispose()
            self.cleanup()

    def testUnModifiedEditedDataTypeReplaced(self):
        try:
            unionNewComplexUnion = Union(new CategoryPath("/aa/aa"), complexUnion.getName())
            unionNewComplexUnion.add(new PointerDataType(), 8)
            unionNewComplexUnion.add(new CharDataType(), 1)

            assertTrue(complexUnion.isEquivalent(model.viewComposite))
            programDTM.replaceDataType(complexUnion, unionNewComplexUnion, True)
            waitForSwing()
            assertTrue(unionNewComplexUnion.isEquivalent(model.viewComposite))

        finally:
            self.cleanup()

if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the Java code provided.