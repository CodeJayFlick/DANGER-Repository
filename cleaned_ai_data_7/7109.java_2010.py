class AnnotationSetReferenceList:
    def __init__(self):
        self.size = None
        self.items = []

    def from_binary_reader(self, reader):
        try:
            self.size = int.from_bytes(reader.read(4), 'little')
            for _ in range(self.size):
                item = AnnotationSetReferenceItem()
                item.from_binary_reader(reader)
                self.items.append(item)
        except Exception as e:
            print(f"Error: {e}")

    def to_data_type(self):
        structure = {"name": f"annotation_set_ref_list_{self.size}", "size": 0}
        for i, item in enumerate(self.items):
            if isinstance(item.to_data_type(), dict):  # assuming item.to_data_type() returns a dictionary
                structure[f"item{i}"] = item.to_data_type()
        return {"category_path": ["/dex/annotation_set_ref_list"], "structure": structure}

    def get_items(self):
        return self.items


class AnnotationSetReferenceItem:
    def __init__(self):
        pass

    def from_binary_reader(self, reader):
        # assuming the implementation of this method
        pass

    def to_data_type(self):
        # assuming the implementation of this method
        pass
