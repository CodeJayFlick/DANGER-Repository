Here is the translation of the Java code into Python:

```Python
class UndoRedoKeeper:
    MAX_UNDO_REDO_SIZE = 50
    STYLE_EDIT_KEY = "style"

    def __init__(self):
        self.undo_stack = []
        self.redo_stack = []
        self.last_style_undo = None

    def add_undo(self, edit):
        name = edit.get_presentation_name()
        if STYLE_EDIT_KEY in name:
            # (see header note about style edits)
            self.add_style_edit(edit)
            return
        else:
            self.end_outstanding_style_edits()

        self.undo_stack.append(edit)
        self.redo_stack.clear()  # new edit added; clear redo

    def end_outstanding_style_edits(self):
        if self.last_style_undo is not None:
            self.last_style_undo.end()
            self.last_style_undo = None
        return

    def add_style_edit(self, edit):
        if self.last_style_undo is None:
            self.last_style_undo = StyleCompoundEdit()
            self.undo_stack.append(self.last_style_undo)
        else:
            self.last_style_undo.add_edit(edit)

        self.redo_stack.clear()  # new edit added; clear redo

    def undo(self):
        if not self.undo_stack:
            return
        self.end_outstanding_style_edits()

        item = self.undo_stack.pop()
        self.redo_stack.append(item)
        item.undo()

        if isinstance(item, StyleCompoundEdit):
            self.undo()  # call again to get a 'real' edit

    def redo(self):
        if not self.redo_stack:
            return
        self.end_outstanding_style_edits()

        item = self.redo_stack.pop()
        self.undo_stack.append(item)
        item.redo()

        if isinstance(item, StyleCompoundEdit):
            self.undo()  # call again to get a 'real' edit

    def clear(self):
        self.undo_stack.clear()
        self.redo_stack.clear()


class StyleCompoundEdit:
    pass
```

Please note that this is not exactly the same as the original Java code. The Python version does not have exact equivalent of `FixedSizeStack` and `UndoableEdit`.