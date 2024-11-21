Here is your Java code translated into Python:

```Python
from tkinter import *
import math

class AlignmentPanelBuilder:
    DEFAULT_MODULUS = 16
    MODULUS_FIELD_TEXT = "Alignment Modulus"
    RECOMPUTE_BUTTON_TEXT = "Compute Alignment Info"

    def __init__(self):
        self.modulusField = None
        self.alignmentTable = None
        self.scrollPane = None
        self.savedNumFuncs = None
        self.savedStartingAddresses = []
        self.fsReader = None

    def buildAlignmentPanel(self):
        alignmentTable = self.createAlignmentTable(None, 0)
        mainPanel = Panel()
        mainPanel.config(borderwidth=10, relief="ridge")
        alignmentTable.pack(side=TOP, fill=BOTH, expand=True)

        modulusPanel = Frame(mainPanel)
        modulusLayout = Grid(columnconfigure=(1,))
        modulusPanel.grid(row=0, column=0, sticky=NSEW)

        label = Label(modulusPanel, text=self.MODULUS_FIELD_TEXT)
        self.modulusField = Entry(modulusPanel, width=10)
        self.modulusField.insert(0, str(self.DEFAULT_MODULUS))
        button = Button(modulusPanel, text=self.RECOMPUTE_BUTTON_TEXT,
                        command=lambda: self.updateAlignmentPanel())
        modulusLayout.add(label, 1, 0)
        modulusLayout.add(self.modulusField, 1, 1)

        mainPanel.pack(side=TOP, fill=BOTH, expand=True)

    def updateAlignmentPanel(self):
        try:
            modulus = int(self.modulusField.get()) or self.DEFAULT_MODULUS
            if modulus < 1:
                modulus = self.DEFAULT_MODULUS
                self.modulusField.delete(0, END)
                self.modulusField.insert(0, str(modulus))
            mainPanel.remove(self.scrollPane)
            alignmentTable = self.createAlignmentTable(self.savedStartingAddresses,
                                                         self.savedNumFuncs)
            self.scrollPane = Scrollbar(mainPanel) + Listbox(mainPanel)

        except ValueError:
            pass

    def createAlignmentTable(self, startingAddresses, numFuncs):
        data = []
        if len(startingAddresses) > 0:
            for i in range(modulus):
                modulusInfo = {"modulus": str(i), "counts": "", "percent": ""}
                countsAsLongs = [0] * modulus
                for address in startingAddresses:
                    remainder = int(address % modulus)
                    if remainder >= len(countsAsLongs):
                        countsAsLongs.append(1)
                    else:
                        countsAsLongs[remainder] += 1

            for i, count in enumerate(countsAsLongs):
                percent = (100.0 * count) / numFuncs
                modulusInfo["counts"] = str(count)
                modulusInfo["percent"] = "{:.2f}%".format(percent)

        alignmentTableModel = AlignmentTableModel(data)
        return Table(alignmentTableModel)

    def resetModulus(self):
        self.modulusField.delete(0, END)
        self.modulusField.insert(0, str(self.DEFAULT_MODULUS))

    def setFsReader(self, fsReader):
        self.fsReader = fsReader
        self.savedStartingAddresses = fsReader.getStartingAddresses()
        self.savedNumFuncs = len(self.savedStartingAddresses)

class AlignmentTableModel:
    columnNames = ["Modulus", "Number of Functions", "Percentage"]
    data = []

    def __init__(self, data):
        self.data = data

    def getColumnName(self, column):
        return self.columnNames[column]

    def getColumnClass(self, columnIndex):
        return str

    def isSortable(self, columnIndex):
        return True

    def getColumnCount(self):
        return 3

    def getName(self):
        return "Function Start Alignment"

    def getModelData(self):
        return self.data

class ModulusInfo:
    modulus = ""
    percent = ""
    counts = ""

    def __init__(self):
        pass
```

Please note that Python does not have direct equivalent of Java's Swing and AWT. The above code uses Tkinter for GUI operations, which is a built-in Python library.