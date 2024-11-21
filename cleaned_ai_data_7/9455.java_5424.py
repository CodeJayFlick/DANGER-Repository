class StringBasedFileEditor:
    def set_value(self, value):
        if not isinstance(value, str):
            raise ValueError("Editor only edits string objects!")
        
        super().set_value(value)

    def get_value(self):
        return self.get_as_text()

# Note: This is a simplified translation and does not include the full functionality of the original Java code.
