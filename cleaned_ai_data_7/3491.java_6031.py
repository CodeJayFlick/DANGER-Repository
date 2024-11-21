import tkinter as tk
from tkinter import messagebox
from typing import List

class ClearDialog:
    def __init__(self, plugin):
        self.plugin = plugin
        self.panel = None
        self.symbolsCb = None
        self.commentsCb = None
        self.propertiesCb = None
        self.codeCb = None
        self.functionsCb = None
        self.registersCb = None
        self.equatesCb = None
        self.userReferencesCb = None
        self.analysisReferencesCb = None
        self.importReferencesCb = None
        self.systemReferencesCb = None
        self.bookmarksCb = None

    def create(self):
        listener = lambda e: self.okCallback() if e.keycode == 13 else None
        self.panel = tk.Frame()
        self.panel.pack(fill="both", expand=True)

        label = tk.Label(self.panel, text="Clear Options:")
        label.pack()

        cbPanel = tk.Frame(self.panel)
        bl = tk.Pack(side=tk.TOP)
        cbPanel.pack(padx=10, pady=(0, 5), fill="x")

        self.symbolsCb = tk.BooleanVar(value=True)
        symbolsCb = tk.Checkbutton(cbPanel, text="Symbols", variable=self.symbolsCb)
        symbolsCb.pack(fill="both", expand=True)

        commentsCb = tk.Checkbutton(cbPanel, text="<HTML>Comments (does not affect automatic comments)</FONT>")
        commentsCb.pack(fill="both", expand=True)

        self.propertiesCb = tk.BooleanVar(value=True)
        propertiesCb = tk.Checkbutton(cbPanel, text="Properties", variable=self.propertiesCb)
        propertiesCb.pack(fill="both", expand=True)

        codeCb = tk.BooleanVar(value=True)
        codeCb.set(True)
        codeCbCB = tk.Checkbutton(cbPanel, text="Code", variable=codeCb)
        codeCbCB.pack(fill="both", expand=True)

        functionsCb = tk.BooleanVar(value=True)
        functionsCbCB = tk.Checkbutton(cbPanel, text="Functions", variable=functionsCb)
        functionsCbCB.pack(fill="both", expand=True)

        registersCb = tk.BooleanVar(value=True)
        registersCbCB = tk.Checkbutton(cbPanel, text="Registers", variable=registersCb)
        registersCbCB.pack(fill="both", expand=True)

        equatesCb = tk.BooleanVar(value=True)
        equatesCbCB = tk.Checkbutton(cbPanel, text="Equates", variable=equatesCb)
        equatesCbCB.pack(fill="both", expand=True)

        userReferencesCb = tk.BooleanVar(value=True)
        userReferencesCb.set(True)
        userReferencesCbCB = tk.Checkbutton(cbPanel, text="User-Defined References", variable=userReferencesCb)
        userReferencesCbCB.pack(fill="both", expand=True)

        analysisReferencesCb = tk.BooleanVar(value=True)
        analysisReferencesCb.set(True)
        analysisReferencesCbCB = tk.Checkbutton(cbPanel, text="Analysis References", variable=analysisReferencesCb)
        analysisReferencesCbCB.pack(fill="both", expand=True)

        importReferencesCb = tk.BooleanVar(value=True)
        importReferencesCb.set(True)
        importReferencesCbCB = tk.Checkbutton(cbPanel, text="Import References", variable=importReferencesCb)
        importReferencesCbCB.pack(fill="both", expand=True)

        systemReferencesCb = tk.BooleanVar(value=True)
        systemReferencesCb.set(True)
        systemReferencesCbCB = tk.Checkbutton(cbPanel, text="Default References", variable=systemReferencesCb)
        systemReferencesCbCB.pack(fill="both", expand=True)

        bookmarksCb = tk.BooleanVar(value=True)
        bookmarksCb.set(True)
        bookmarksCbCB = tk.Checkbutton(cbPanel, text="Bookmarks", variable=bookmarksCb)
        bookmarksCbCB.pack(fill="both", expand=True)

    def okCallback(self):
        self.panel.destroy()
        opts = ClearOptions()

        if codeCb.get():
            userReferencesCb.set(True)
            analysisReferencesCb.set(True)
            importReferencesCb.set(True)
            systemReferencesCb.set(True)
        else:
            userReferencesCbCB.config(state="normal")
            analysisReferencesCbCB.config(state="normal")
            importReferencesCbCB.config(state="normal")
            systemReferencesCbCB.config(state="normal")

    def cancelCallback(self):
        self.panel.destroy()

class ClearOptions:
    pass

# Usage
plugin = None  # Your plugin instance here
dialog = ClearDialog(plugin)
dialog.create()
