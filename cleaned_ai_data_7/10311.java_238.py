class PropertyText:
    def __init__(self, pe):
        self.editor = pe
        self.is_editing = False

    def set_text(self, text):
        if not self.is_editing:
            self.text = text

    def update(self):
        self.is_editing = True
        try:
            self.editor.set_as_text(self.text)
        except Exception as e:
            pass  # ignore exceptions
        finally:
            self.is_editing = False


class UpdateDocumentListener:
    def __init__(self, property_text):
        self.property_text = property_text

    def insert_update(self, event):
        self.update()

    def remove_update(self, event):
        self.update()

    def changed_update(self, event):
        self.update()

    def update(self):
        if not self.property_text.is_editing:
            try:
                self.property_text.editor.set_as_text(self.property_text.text)
            except Exception as e:
                pass  # ignore exceptions
            finally:
                self.property_text.is_editing = False


class PropertyEditor:
    def __init__(self, value):
        self.value = value

    def get_as_text(self):
        return str(self.value)

    def set_as_text(self, text):
        try:
            self.value = int(text)
        except ValueError as e:
            pass  # ignore exceptions
