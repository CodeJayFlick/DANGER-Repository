Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview, Button, Label
from tkinter import simpledialog

class ErrLogExpandableDialog:
    def __init__(self, title, msg, throwable):
        self.baseTitle = title
        self.errors = [throwable]
        
        # Create the main window
        self.root = tk.Tk()
        self.root.title(title)
        
        # Create a frame for the message panel
        self.msgPanel = tk.Frame(self.root)
        self.msgPanel.pack(fill=tk.BOTH, expand=True)

        # Add the message label and buttons to the message panel
        self.label = Label(self.msgPanel, text=msg)
        self.label.pack()
        
        self.sendButton = Button(self.msgPanel, text="Send Report...", command=self.sendCallback)
        self.sendButton.pack(side=tk.LEFT)
        
        self.detailButton = Button(self.msgPanel, text="Details >>", command=self.detailCallback)
        self.detailButton.pack(side=tk.RIGHT)

    def getHTML(self, msg, report):
        html = "<html><body>"
        if msg:
            if not msg.startswith("<html>"):
                for line in addBR(msg).splitlines():
                    html += f"<p>{line}</p>\n"
            else:
                html += msg
        for t in report:
            tMsg = self.getMessage(t)
            if SystemUtilities.isEqual(msg, tMsg):
                continue
            for line in addBR(tMsg).splitlines():
                html += f"<p>{line}</p>\n"
        return html + "</body></html>"

    def addBR(self, text):
        with open("temp.txt", "w") as file:
            file.write(text)
        temp = ScrolledText(self.root, width=80, height=10)
        temp.insert('1.0', text)
        temp.pack()
        return temp.get('1.0', 'end-1c')

    def getMessage(self, t):
        if t.getMessage():
            return t.getMessage()
        else:
            return str(t.getClass().getSimpleName())

    def detailCallback(self):
        self.showingDetails = not self.showingDetails
        self.tree.setVisible(self.showingDetails)
        self.horizontalSpacer.pack(self.showingDetails)
        self.detailButton.config(text=self.showingDetails and "<<< Details" or "Details >>")

    def sendCallback(self):
        details = self.root.collectReportText(None, 0).strip()
        title = self.baseTitle
        close()
        ErrLogDialog.getErrorReporter().report(rootPanel, title, details)

class ReportRootNode:
    def __init__(self, title, report):
        self.title = title
        self.report = report

    def collectReportText(self, included=None, indent=0):
        return Util.collectReportText(self, included, indent)

def addBR(text):
    with open("temp.txt", "w") as file:
        file.write(text)
    temp = ScrolledText(root, width=80, height=10)
    temp.insert('1.0', text)
    temp.pack()
    return temp.get('1.0', 'end-1c')

def getMessage(t):
    if t.getMessage():
        return t.getMessage()
    else:
        return str(t.getClass().getSimpleName())

class ReportExceptionNode:
    def __init__(self, cause):
        self.cause = cause

    def collectReportText(self, included=None, indent=0):
        return Util.collectReportText(self, included, indent)

def getTransferData(transferNodes, flavor):
    if flavor != DataFlavor.stringFlavor:
        raise UnsupportedFlavorException(flavor)
    if transferNodes.empty():
        return None
    if transferNodes.size() == 1:
        node = transferNodes.get(0)
        if isinstance(node, NodeWithText):
            return (node.collectReportText(transferNodes, 0).strip())
        else:
            return None
    return root.collectReportText(transferNodes, 0).strip()

class TransferActionListener:
    def __init__(self):
        self.focusOwner = None

    def propertyChange(self, e):
        o = e.getNewValue()
        if isinstance(o, tk.Widget):
            self.focusOwner = o
        else:
            self.focusOwner = None

    def actionPerformed(self, e):
        if not self.focusOwner:
            return
        action = e.getActionCommand()
        a = self.focusOwner.get_action_map().get(action)
        if a is not None:
            a.action_performed(new ActionEvent(self.focusOwner, ActionEvent.ACTION_PERFORMED, None))

root = tk.Tk()

ErrLogExpandableDialog("Title", "Message", Exception()).pack(fill=tk.BOTH, expand=True)

root.mainloop()
```

Please note that the translation of Java code to Python is not always straightforward. The above code may need some adjustments based on your specific requirements and environment.