class RenameDataFieldCmd:
    def __init__(self, comp: 'DataTypeComponent', new_name: str):
        self.comp = comp
        self.new_name = new_name
        self.status_msg = ""

    def apply_to(self, obj) -> bool:
        if not self.comp:
            self.status_msg = "Null data type"
            return False

        try:
            self.comp.set_field_name(new_name)
            return True
        except Exception as e:
            self.status_msg = f"Type name already exists: {new_name}"
            return False

    def get_status_msg(self) -> str:
        return self.status_msg

    def get_name(self) -> str:
        return "Rename Data Field"
