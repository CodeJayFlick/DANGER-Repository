class TypeLookupTable_Pie:
    def __init__(self):
        self.dex_data_begin = None
        self.raw_data_length = None
        self.mask = None
        self.entries = []
        self.owns_entries = False

    @property
    def dex_data_begin(self):
        return self.dex_data_begin_

    @dex_data_begin.setter
    def dex_data_begin(self, value):
        self.dex_data_begin_ = value

    @property
    def raw_data_length(self):
        return self.raw_data_length_

    @raw_data_length.setter
    def raw_data_length(self, value):
        self.raw_data_length_ = value

    @property
    def mask(self):
        return self.mask_

    @mask.setter
    def mask(self, value):
        self.mask_ = value

    @property
    def entries(self):
        return self.entries_

    @entries.setter
    def entries(self, value):
        if isinstance(value, list) and all(isinstance(x, dict) for x in value):
            self.entries_ = value
        else:
            raise ValueError("Entries must be a list of dictionaries")

    @property
    def owns_entries(self):
        return self.owns_entries_

    @owns_entries.setter
    def owns_entries(self, value):
        if isinstance(value, bool):
            self.owns_entries_ = value
        else:
            raise ValueError("Owns entries must be a boolean")

    def to_data_type(self) -> dict:
        data_type = {
            "dex_data_begin": {"type": "int", "value": self.dex_data_begin},
            "raw_data_length": {"type": "int", "value": self.raw_data_length},
            "mask": {"type": "int", "value": self.mask}
        }
        for i, entry in enumerate(self.entries):
            data_type[f"entry_{i}"] = {"type": "dict", "value": entry}
        data_type["owns_entries"] = {"type": "bool", "value": self.owns_entries}
        return data_type
