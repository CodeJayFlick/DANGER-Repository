class UID:
    def __init__(self, bytes):
        self.bytes = bytes

    def get_type(self):
        return "UID"

    def to_data_type(self) -> dict:
        structure = {"name": f"UID{len(self.bytes)}", "length": 0}
        array = {"type": "byte", "length": len(self.bytes), "name": "UID"}
        structure["children"] = [array]
        return structure

    def __str__(self):
        return str(self.bytes)
