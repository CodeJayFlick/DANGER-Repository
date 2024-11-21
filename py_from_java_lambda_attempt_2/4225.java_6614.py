Here is the translation of the Java code into Python:

```Python
from tkinter import *
import tkinter.messagebox as tkmb

class ScalarSearchDialog:
    def __init__(self, plugin):
        self.plugin = plugin
        self.mainPanel = Frame(self)
        self.exactValueField = IntVar()
        self.minField = StringVar()
        self.maxField = StringVar()

        self.searchAllScalars = BooleanVar()
        self.searchAScalar = BooleanVar()
        self.searchSelectionRadioButton = Radiobutton(self, text="Search Selection", variable=self.searchAllScalars)
        self.searchAllRadioButton = Radiobutton(self, text="Search All", variable=self.searchAllScalars)

    def show(self):
        clearStatusText()
        exactValueField.focus_set()
        exactValueField.select_range(0, END)
        PluginTool(tool).showDialog(self, provider)

    def setFilterValues(self, min_filter_value, max_filter_value):
        self.minField.set(str(min_filter_value))
        self.maxField.set(str(max_filter_value))

    def setSpecificScalarValue(self, value):
        exactValueField.set(value)

    def setSearchAScalar(self):
        searchAScalar.set(True)
        exactValueField.config(state='normal')
        minField.config(state='disabled')
        maxField.config(state='disabled')

    def getProvider(self):
        return provider

    def buildMainPanel(self):
        newMainPanel = Frame()
        newMainPanel.pack(fill=BOTH, expand=1)

        searchLayout = SearchPanel(newMainPanel)
        selectionPanel = self.buildSelectionPanel()

        newMainPanel.add(searchLayout, 'n')
        newMainPanel.add(selectionPanel, 's')

    def buildSearchLayout(self):
        return Frame()

    def createMinFilterWidget(self):
        minField.set('0')
        return Entry(minField)

    def createMaxFilterWidget(self):
        maxField.set('10000000')
        return Entry(maxField)

    def buildSelectionPanel(self):
        panel = Frame()
        panel.pack(fill=BOTH, expand=1)
        panel.config(borderwidth=2, relief='ridge')

        searchAllRadioButton = Radiobutton(panel, text="Search All", variable=self.searchAllScalars)
        searchSelectionRadioButton = Radiobutton(panel, text="Search Selection", variable=self.searchAllScalars)

    def buildSearchButton(self):
        beginSearchButton = Button()
        beginSearchButton.config(text='Search', command=lambda: self.searchCallback())

    def searchCallback(self):
        if self.searchAllRadioButton.get():
            provider = ScalarSearchProvider(plugin)
            updateProviderFilterValues()
            provider.setVisible(True)
            close()

        elif self.searchSelectionRadioButton.get():
            current_selection = plugin.getProgramSelection()
            if current_selection is None:
                setStatusText(NULL_SELECTION)

    def updateProviderFilterValues(self):
        pass

    def getMinSearchValue(self):
        return int(minField.get())

    def getMaxSearchValue(self):
        return int(maxField.get())

    def getMinSearchValueText(self):
        return minField.get()

    def getMaxSearchValueText(self):
        return maxField.get()


class SearchPanel:
    def __init__(self, parent):
        self.parent = parent
        self.searchAllScalars = BooleanVar()
        self.searchAScalar = BooleanVar()

        panel = Frame(parent)
        panel.pack(fill=BOTH, expand=1)

        searchAllScalars.set(True)
        exactValueField = IntVar()


class RangeFilter:
    def __init__(self):
        pass


if __name__ == "__main__":
    root = Tk()
    plugin = None
    provider = None

    dialog = ScalarSearchDialog(plugin)
    dialog.buildMainPanel()

    root.mainloop()
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an interpretation, as the original code was written in Java and some parts might be missing or modified for better compatibility with Python.

Also, please note that you will need to have tkinter installed (`pip install tk`) to run this script.