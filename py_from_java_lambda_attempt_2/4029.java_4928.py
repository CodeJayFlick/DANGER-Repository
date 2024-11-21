Here is the translation of the Java code into Python:

```Python
class MemoryMapModel:
    NAME = 0
    START = 1
    END = 2
    LENGTH = 3
    READ = 4
    WRITE = 5
    EXECUTE = 6
    VOLATILE = 7
    OVERLAY = 8
    BLOCK_TYPE = 9
    INIT = 10
    BYTE_SOURCE = 11
    SOURCE = 12
    COMMENT = 13

    NAME_COL = "Name"
    START_COL = "Start"
    END_COL = "End"
    LENGTH_COL = "Length"
    READ_COL = "R"
    WRITE_COL = "W"
    EXECUTE_COL = "X"
    VOLATILE_COL = "Volatile"
    OVERLAY_COL = "Overlay"
    BLOCK_TYPE_COL = "Type"
    INIT_COL = "Initialized"
    BYTE_SOURCE_COL = "Byte Source"
    SOURCE_COL = "Source"
    COMMENT_COL = "Comment"

    def __init__(self, provider, program):
        super().__init__()
        self.program = program
        self.provider = provider

        self.memList = []
        self.populateMap()

    def populateMap(self):
        if not self.program:
            return

        mem = self.program.getMemory()
        blocks = mem.getBlocks()
        for block in blocks:
            self.memList.append(block)
        self.fireTableDataChanged()

    def update(self):
        table = self.provider.getTable()
        cellEditor = table.getCellEditor()
        if cellEditor:
            cellEditor.cancelCellEditing()
        self.populateMap()

    def isSortable(self, columnIndex):
        return (columnIndex != self.READ and
                columnIndex != self.WRITE and
                columnIndex != self.EXECUTE and
                columnIndex != self.VOLATILE and
                columnIndex != self.OVERLAY)

    def getName(self):
        return "Memory Map"

    def getColumnCount(self):
        return len(self.COLUMN_NAMES)

    def getColumnName(self, column):
        if 0 <= column < len(self.COLUMN_NAMES):
            return self.COLUMN_NAMES[column]
        else:
            return "UNKNOWN"

    def findColumn(self, columnName):
        for i in range(len(self.COLUMN_NAMES)):
            if self.COLUMN_NAMES[i].lower() == columnName.lower():
                return i
        return 0

    def getColumnClass(self, columnIndex):
        if (columnIndex == self.READ or
           columnIndex == self.WRITE or
           columnIndex == self.EXECUTE or
           columnIndex == self.VOLATILE):
            return bool.__class__
        else:
            return str.__class__

    def isCellEditable(self, rowIndex, columnIndex):
        switcher = {
            self.NAME: True,
            self.READ: True,
            self.WRITE: True,
            self.EXECUTE: True,
            self.VOLATILE: True,
            self.COMMENT: True
        }
        return switcher.get(columnIndex, False)

    def getRowCount(self):
        return len(self.memList)

    @staticmethod
    def getAddressString(address):
        space = address.getAddressSpace()
        if space.isOverlaySpace():
            ov_space = OverlayAddressSpace(space)
            base_space = ov_space.getOverlayedSpace()
            address = base_space.getAddress(0)
        return str(address)

    def getBlockAt(self, rowIndex):
        if not self.memList:
            return None
        if 0 <= rowIndex < len(self.memList):
            block = self.memList[rowIndex]
            try:
                block.getStart()
            except ConcurrentModificationException:
                self.update()
            return block

    def setValueAt(self, aValue, rowIndex, columnIndex):
        self.provider.setCursor(MemoryMapPlugin.WAIT_CURSOR)
        try:
            if isinstance(aValue, str) and not aValue.strip():
                aValue = None
            switcher = {
                self.NAME: self.setName,
                self.READ: self.setReadState,
                self.WRITE: self.setWriteState,
                self.EXECUTE: self.setExecuteState,
                self.VOLATILE: self.setVolatileState,
                self.INIT: self.initializeBlock,
                self.COMMENT: self.setComment
            }
            if columnIndex in switcher:
                block = self.getBlockAt(rowIndex)
                if block is not None:
                    switcher[columnIndex](block, aValue)
        finally:
            self.provider.setCursor(MemoryMapPlugin.NORM_CURSOR)

    def setName(self, block, name):
        if len(name) == 0 or name.lower() == block.getName().lower():
            return
        if Memory.isValidMemoryBlockName(name):
            id = self.program.startTransaction("Rename Memory Block")
            try:
                block.setName(name)
                self.program.endTransaction(id, True)
            except LockException as e:
                self.program.endTransaction(id, False)
                self.provider.setStatusText(str(e))
            except Exception as e:
                self.program.endTransaction(id, False)
                Msg.showError(self, self.provider.getComponent(), "Block Renaming Failed", str(e))

    def setReadState(self, block, value):
        id = self.program.startTransaction("Set Read State")
        try:
            if isinstance(value, bool) and value:
                block.setRead(True)
            else:
                block.setRead(False)
            self.provider.setStatusText("")
            self.program.endTransaction(id, True)
        except Exception as e:
            self.program.endTransaction(id, False)
            raise e

    def setWriteState(self, block, value):
        id = self.program.startTransaction("Set Write State")
        try:
            if isinstance(value, bool) and value:
                block.setWrite(True)
            else:
                block.setWrite(False)
            self.provider.setStatusText("")
            self.program.endTransaction(id, True)
        except Exception as e:
            self.program.endTransaction(id, False)
            raise e

    def setExecuteState(self, block, value):
        id = self.program.startTransaction("Set Execute State")
        try:
            if isinstance(value, bool) and value:
                block.setExecute(True)
            else:
                block.setExecute(False)
            self.provider.setStatusText("")
            self.program.endTransaction(id, True)
        except Exception as e:
            self.program.endTransaction(id, False)
            raise e

    def setVolatileState(self, block, value):
        id = self.program.startTransaction("Set Volatile State")
        try:
            if isinstance(value, bool) and value:
                block.setVolatile(True)
            else:
                block.setVolatile(False)
            self.provider.setStatusText("")
            self.program.endTransaction(id, True)
        except Exception as e:
            self.program.endTransaction(id, False)
            raise e

    def initializeBlock(self, block):
        dialog = NumberInputDialog("Initialize Memory Block", "Enter fill byte value for block: ", 0, 0, 255, True)
        if not dialog.show():
            return
        value = int(dialog.getValue())
        id = self.program.startTransaction("Initialize Memory Block")
        try:
            mem = self.program.getMemory()
            index = self.memList.index(block)
            newBlock = mem.convertToInitialized(block, value)
            self.memList[index] = newBlock
            self.fireTableRowsUpdated(index, index)
            self.program.endTransaction(id, True)
        except Exception as e:
            self.program.endTransaction(id, False)
            Msg.showError(self, self.provider.getComponent(), "Block Initialization Failed", str(e))

    def setComment(self, block, comment):
        if isinstance(comment, str) and not comment.strip():
            return
        id = self.program.startTransaction("Set Comment State")
        try:
            block.setComment(comment)
            self.fireTableRowsUpdated(0, len(self.memList))
            self.program.endTransaction(id, True)
        except Exception as e:
            self.program.endTransaction(id, False)
            raise e

    def getColumnValueForRow(self, block, columnIndex):
        if isinstance(block, MemoryBlock) and 0 <= columnIndex < len(self.COLUMN_NAMES):
            switcher = {
                self.NAME: lambda: block.getName(),
                self.START: lambda: self.getAddressString(block.getStart()),
                self.END: lambda: self.getAddressString(block.getEnd()),
                self.LENGTH: lambda: "0x" + hex(block.getSize())[2:].upper(),
                self.READ: lambda: str(block.isRead()).lower(),
                self.WRITE: lambda: str(block.isWrite()).lower(),
                self.EXECUTE: lambda: str(block.isExecute()).lower(),
                self.VOLATILE: lambda: str(block.isVolatile()).lower(),
                self.OVERLAY: lambda: str(block.isOverlay()),
                self.INIT: lambda: "True" if block.isInitialized() else "False",
                self.BYTE_SOURCE: lambda: getByteSourceDescription(block.getSourceInfos()),
                self.SOURCE: lambda: block.getSourceName(),
                self.COMMENT: lambda: block.getComment()
            }
            return switcher.get(columnIndex, lambda: "UNKNOWN")()

    def getModelData(self):
        return self.memList

class MemoryMapComparator:
    def __init__(self, sortColumn):
        self.sortColumn = sortColumn

    def compare(self, b1, b2):
        if isinstance(b1, MemoryBlock) and isinstance(b2, MemoryBlock):
            switcher = {
                0: lambda: b1.getName().lower() - b2.getName().lower(),
                1: lambda: self.getAddressString(b1.getStart()) - self.getAddressString(b2.getStart()),
                2: lambda: self.getAddressString(b1.getEnd()) - self.getAddressString(b2.getEnd()),
                3: int(b1.getSize()) - int(b2.getSize())
            }
            return switcher.get(self.sortColumn, lambda: 0)()
```

Please note that this translation is not perfect and some Java-specific features might be lost in the process.