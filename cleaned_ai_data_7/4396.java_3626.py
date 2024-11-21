import tkinter as tk
from tkinter import messagebox
from typing import Dict, List

class FilterDialog:
    def __init__(self, tool):
        self.tool = tool
        self.filter = NewSymbolFilter()
        self.advancedPanel = None
        self.checkBoxMap: Dict[str, tk.Checkbutton] = {}
        self.ignoreCallbacks = False
        self.isChanged = True
        self.keyModel = None

    def setStatusText(self, text):
        super().setStatusText(text)

    def setFilter(self, new_filter):
        self.filter = NewSymbolFilter(new_filter)
        self.initCheckBoxes()
        self.setChanged(True)

    def saveFilter(self) -> str:
        return self.filter.saveToXml()

    def restoreFilter(self, element: str):
        self.filter.restoreFromXml(element)
        self.initCheckBoxes()

    def initCheckBoxes(self):
        self.isChanged = False
        self.ignoreCallbacks = True

        for filter_name in list(self.checkBoxMap.keys()):
            cb = self.checkBoxMap[filter_name]
            selected = self.filter.isActive(filter_name)
            cb.select(selected)

        self.ignoreCallbacks = False
        advanced_filter_count = len([f for f in self.filter.getAdvancedFilterNames() if self.filter.getActive(0)])
        self.advancedFilterCheckbox.select(advanced_filter_count > 0)

    def buildWorkPanel(self) -> tk.Frame:
        panel = tk.Frame()
        panel.pack(fill=tk.X, expand=True)
        advanced_checkbox = tk.Checkbutton(panel, text="Use Advanced Filters")
        advanced_checkbox.pack(side=tk.LEFT)
        advanced_checkbox.config(command=lambda: self.onAdvancedFilterChange(advanced_checkbox))
        return panel

    def onAdvancedFilterChange(self, checkbox):
        if not self.ignoreCallbacks:
            selected = checkbox.instate()[0]
            if selected:
                self.advancedPanel.add(tk.Frame())
            else:
                for child in list(self.advancedPanel.winfo_children()):
                    child.destroy()
            self.repack()

    def buildSourcePanel(self) -> tk.Frame:
        panel = tk.Frame()
        panel.pack(fill=tk.X, expand=True)
        source_names = [f"Source {i}" for i in range(5)]
        for name in source_names:
            cb = tk.Checkbutton(panel, text=name)
            self.checkBoxMap[name] = cb
            cb.config(command=lambda f=cb: self.onFilterChange(f))
            panel.pack(side=tk.LEFT)

    def onFilterChange(self, checkbox):
        if not self.ignoreCallbacks:
            selected = checkbox.instate()[0]
            filter_name = checkbox.cget("text")
            self.setChanged(True)
            self.filter.setFilter(filter_name, selected)
            self.update()

    # ... rest of the code ...

class NewSymbolFilter:
    def __init__(self):
        pass

    def saveToXml(self) -> str:
        return ""

    def restoreFromXml(self, element: str):
        pass

    def isActive(self, filter_name: str) -> bool:
        return False

    # ... rest of the code ...

class SymbolTableModel:
    def __init__(self):
        pass

    def getFilter(self) -> NewSymbolFilter:
        return None
