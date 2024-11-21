Here is the translation of the given Java code into Python:

```Python
class ImportDialogButtonEnablerListener:
    def __init__(self, password_view, dialog):
        self.password_view = password_view
        self.dialog = dialog
        self.handle()

    def on_selected(self, parent, view, position, id):
        self.handle()

    def nothing_selected(self, parent):
        self.handle()

    def after_text_changed(self, s):
        self.handle()

    def before_text_changed(self, s, start, count, after):
        pass

    def text_changed(self, s, start, before, count):
        pass

    def handle(self):
        needs_password = self.needs_password()
        has_password = not (self.password_view.get_text().strip() == '')
        has_file = self.has_file()

        button = self.dialog.get_button(1)
        button.config(state='normal' if has_file and (not needs_password or has_password) else 'disabled')

    def has_file(self):
        return True

    def needs_password(self):
        return True
```

Please note that Python does not have direct equivalents for Java's `AlertDialog`, `AdapterView`, `OnItemSelectedListener` etc. So, I had to make some adjustments and use built-in Python functions instead.