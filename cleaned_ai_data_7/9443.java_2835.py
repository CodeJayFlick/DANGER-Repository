from tkinter import *
import os

class FontPropertyEditor:
    def __init__(self):
        self.font = None
#       self.previewLabel  = Label()
        self.previewButton = Button(text="ABCabc \u00a9\u00ab\u00a7\u0429\u05d1\u062c\u4eb9", command=self.show_dialog)

    def showDialog(self, event=None):
        provider = EditorProvider(FontPanel())
        DockingWindowManager().showDialog(self.previewButton, provider)
        self.previewButton.config(text="ABCabc  \u00a9\u00ab\u00a7\u0429\u05d1\u062c\u4eb9", font=self.font)

    def set_value(self, o):
        if isinstance(o, Font):
            self.font = o
            self.previewButton.config(font=self.font)
#           # set the font values on the widget

    def get_value(self):
        return self.font


class EditorProvider:
    def __init__(self, contentPanel):
        super().__init__("Font Editor", True)

        self.add_work_panel(contentPanel)
        self.add_ok_button()
        self.add_cancel_button()

    def ok_callback(self):
        self.close()

    def cancel_callback(self):
        self.font = original_font
        super().cancel_callback()


class FontWrapper:
    def __init__(self, font_name):
        self.font_name = font_name

    def get_font_name(self):
        return self.font_name


class FontPanel:
    def __init__(self):
        self.init()

    def init(self):
        panel = Frame()
        panel.pack(fill=BOTH)

        top_panel = Frame(panel)
        top_panel.pack(side=TOP, fill=X)

        font_label = Label(top_panel, text="Fonts")
        size_and_style_panel = Frame(panel)
        style_label = Label(size_and_style_panel, text="Styles")

        self.fonts = StringVar()
        fonts_combobox = Combobox(top_panel, textvariable=self.fonts)
        for envfont in os.environ['PATH'].split(os.sep):
            if envfont:
                font_wrapper = FontWrapper(envfont)
                self.fonts.set(font_wrapper.get_font_name())
                break

        size_label = Label(size_and_style_panel, text="Sizes")
        sizes_combobox = Combobox(size_and_style_panel)

        for i in range(1, 73):
            sizes_combobox.add(i)

        style_combobox = Combobox(size_and_style_panel)
        styles = ["PLAIN", "BOLD", "ITALIC", "BOLD & ITALIC"]
        for s in styles:
            style_combobox.add(s)

        top_panel.pack(side=TOP, fill=X)
        panel.pack(fill=BOTH)


class FontPropertyEditorSupport:
    def __init__(self):
        pass

#   @Override
#   public void firePropertyChange() {
#
#   }
