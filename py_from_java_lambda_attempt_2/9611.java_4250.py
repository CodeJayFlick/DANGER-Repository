Here is a translation of the Java code into equivalent Python code:

```Python
class DirectoryTable:
    def __init__(self, chooser, model):
        self.chooser = chooser
        self.model = model
        super().__init__(model)
        self.build()

    def build(self):
        self.setAutoLookupColumn(0)  # Assuming the first column is FILE_ COL

        self.setSelectionMode("SINGLE_SELECTION")
        self.setShowGrid(False)

        self.addMouseListener(MouseAdapter())
        self.addMouseListener(GMouseListenerAdapter())

        self.addKeyListener(KeyAdapter())

        editor = FileEditor(self.chooser, self, self.model)
        self.getColumnModel().getColumn(0).setCellRenderer(FileTableCellRenderer(self.chooser))
        self.getColumnModel().getColumn(0).setCellEditor(editor)

    def createAutoLookup(self):
        return GTableAutoLookup(self)  # Assuming this is a class

class AutoLookup:
    pass

class MouseAdapter:
    def mouseClicked(self, e):
        editingCanceled(None)
        requestFocus()

class GMouseListenerAdapter:
    def shouldConsume(self, e):
        if e.isPopupTrigger() and self.isEditing():
            return True
        return False

    def popupTriggered(self, e):
        maybeSelectItem(e)

    def doubleClickTriggered(self, e):
        handleDoubleClick()

class KeyAdapter:
    def keyPressed(self, e):
        if e.getKeyCode() != KeyEvent.VK_ENTER:
            return
        e.consume()
        selectedRows = self.getSelectedRows()
        if len(selectedRows) == 0:
            chooser.okCallback()
        elif len(selectedRows) > 1:
            chooser.okCallback()
        else:
            file = model.getFile(0)
            if chooser.getModel().isDirectory(file):
                chooser.setCurrentDirectory(file)
            else:
                chooser.userChoseFile(file)

class FileEditor:
    def __init__(self, chooser, table, model):
        self.chooser = chooser
        self.table = table
        self.model = model

    # Other methods...

class GTableAutoLookup:
    pass

def maybeSelectItem(e):
    point = e.getPoint()
    row = self.rowAtPoint(point)
    if row < 0:
        return
    selectRow(row)

def updateChooserForSelection():
    selectedFiles = []
    for i in getSelectedRows():
        file = model.getFile(i)
        selectedFiles.append(file)
    chooser.userSelectedFiles(selectedFiles)

def handleDoubleClick():
    selectedFiles = []
    for i in getSelectedRows():
        file = model.getFile(i)
        selectedFiles.append(file)
    if len(selectedFiles) == 0 or len(selectedFiles) > 1:
        return
    file = selectedFiles[0]
    if chooser.getModel().isDirectory(file):
        chooser.setCurrentDirectory(file)
    else:
        chooser.userChoseFile(file)

def setRowToEdit(rowToEdit):
    self.rowToEdit = rowToEdit

def getSelectedFile():
    row = getSelectedRow()
    if row < 0:
        return None
    file = model.getFile(0)  # Assuming the first column is FILE_ COL
    return file

# Other methods...
```

Please note that this translation assumes some classes and methods are defined elsewhere in your code.