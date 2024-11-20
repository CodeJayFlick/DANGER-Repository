import unittest
from ghidra.app.plugin.core.compositeeditor import *
from ghidra.program.model.data import *
from ghidra.util.exception import DuplicateNameException
from ghidra.program.model.symbol import ExternalLocation, SourceType
from ghidra.program.model.listing import Function, Library

class StructureEditorLockedCellEditTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.dir = getDebugFileDirectory()
        self.dir.mkdir()

    @unittest.skip("Not implemented")
    def init(self, dt, cat):
        commit = True
        try:
            dataTypeManager = cat.getDataTypeManager()
            if dt.getDataTypeManager() != dataTypeManager:
                dt = dt.clone(dataTypeID)
            categoryPath = cat.getCategoryPath()
            if not dt.getCategoryPath().equals(categoryPath):
                raise DuplicateNameException("Duplicate name exception")
        finally:
            endTransaction(commit)

    def testF2EditKey(self):
        init(simpleStructure, pgmBbCat)
        colNum = model.getDataTypeColumn()

        setSelection([0])
        checkSelection([0])
        self.assertTrue(editFieldAction.isEnabled())
        triggerActionKey(getTable(), editFieldAction)
        assertIsEditingField(0, colNum)

    def testEditComponentDataTypeInvalid(self):
        init(simpleStructure, pgmBbCat)
        column = model.getDataTypeColumn()
        str = "AbCdEfG_12345.,/\\""
        row = 2
        dtLength = 4

        assertEquals(29, model.getLength())
        assertEquals(dtLength, getDataType(row).getLength())

    def testEditComponentName(self):
        init(simpleStructure, pgmBbCat)
        column = model.getNameColumn()
        num = model.getNumComponents()

        clickTableCell(getTable(), row=3, column=column)

        setText("Wow")
        enter()

        assertNotEditingField()
        assertEquals(1, model.getNumSelectedRows())
        assertEquals(row=3, model.getMinIndexSelected())

    def testEditComponentComment(self):
        init(simpleStructure, pgmBbCat)
        column = model.getCommentColumn()
        num = model.getNumComponents()

        clickTableCell(getTable(), row=3, column=column)

        setText("My comment.")
        enter()

        assertNotEditingField()
        assertEquals(1, model.getNumSelectedRows())
        assertEquals(row=3, model.getMinIndexSelected())

    def testEditNextField(self):
        init(simpleStructure, pgmBbCat)
        row = 3
        colNum = model.getNameColumn()

        clickTableCell(getTable(), row=row, column=colNum)

        setText("Component_3")
        triggerActionInCellEditor(KeyEvent.VK_TAB)

    def testEditPreviousField(self):
        init(simpleStructure, pgmBbCat)
        row = 3
        colNum = model.getNameColumn()

        clickTableCell(getTable(), row=row, column=colNum)

        setText("Component_3")
        triggerActionInCellEditor(InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB)

    def testEditUpField(self):
        init(simpleStructure, pgmBbCat)
        row = 3
        colNum = model.getNameColumn()

        clickTableCell(getTable(), row=row, column=colNum)

        setText("Component_3")
        triggerActionInCellEditor(KeyEvent.VK_UP)

    def testEditDownField(self):
        init(simpleStructure, pgmBbCat)
        row = 3
        colNum = model.getNameColumn()

        clickTableCell(getTable(), row=row, column=colNum)

        setText("Component_3")
        triggerActionInCellEditor(KeyEvent.VK_DOWN)

    def testEditReorderedColumns(self):
        init(simpleStructure, pgmBbCat)
        table = getTable()
        runSwing(lambda: table.moveColumn(4, 1))
        runSwing(lambda: table.moveColumn(5, 3))

        doubleClickTableCell(row=3, column=model.getNameColumn())

        assertIsEditingField(row=3, column=model.getNameColumn())
