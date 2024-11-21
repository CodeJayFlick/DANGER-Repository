class AnnotationsDirectoryItem:
    def __init__(self):
        self.class_annotations_offset = None
        self.fields_size = None
        self.annotated_methods_size = None
        self.annotated_parameters_size = None
        self.field_annotations = []
        self.method_annotations = []
        self.parameter_annotations = []

    def from_binary_reader(self, reader):
        if isinstance(reader, int):  # Assuming the first argument is an integer.
            return

        try:
            self.class_annotations_offset = reader.read_int()
            self.fields_size = reader.read_int()
            self.annotated_methods_size = reader.read_int()
            self.annotated_parameters_size = reader.read_int()

            for _ in range(self.fields_size):
                field_annotation = FieldAnnotationsItem(reader)
                self.field_annotations.append(field_annotation)

            for _ in range(self.annotated_methods_size):
                method_annotation = MethodAnnotationsItem(reader)
                self.method_annotations.append(method_annotation)

            if self.class_annotations_offset > 0:
                old_index = reader.get_pointer_index()
                try:
                    reader.set_pointer_index(DexUtil.adjust_offset(self.class_annotations_offset))
                    class_annotations = AnnotationSetItem(reader, DexHeader())
                    self._class_annotations = class_annotations
                finally:
                    reader.set_pointer_index(old_index)
        except Exception as e:
            print(f"An error occurred: {e}")

    def get_class_annotations_offset(self):
        return self.class_annotations_offset

    def get_fields_size(self):
        return self.fields_size

    def get_annotated_methods_size(self):
        return self.annotated_methods_size

    def get_annotated_parameters_size(self):
        return self.annotated_parameters_size

    @property
    def field_annotations(self):
        return tuple(self.field_annotations)

    @field_annotations.setter
    def field_annotations(self, value):
        if isinstance(value, list) and all(isinstance(x, FieldAnnotationsItem) for x in value):
            self._field_annotations = value
        else:
            raise ValueError("Invalid type. It should be a list of FieldAnnotationsItems.")

    @property
    def method_annotations(self):
        return tuple(self.method_annotations)

    @method_annotations.setter
    def method_annotations(self, value):
        if isinstance(value, list) and all(isinstance(x, MethodAnnotationsItem) for x in value):
            self._method_annotations = value
        else:
            raise ValueError("Invalid type. It should be a list of MethodAnnotationsItems.")

    @property
    def parameter_annotations(self):
        return tuple(self.parameter_annotations)

    @parameter_annotations.setter
    def parameter_annotations(self, value):
        if isinstance(value, list) and all(isinstance(x, ParameterAnnotationsItem) for x in value):
            self._parameter_annotations = value
        else:
            raise ValueError("Invalid type. It should be a list of ParameterAnnotationsItems.")

    @property
    def class_annotations(self):
        return self._class_annotations

    def to_data_type(self):
        structure = {"name": f"annotations_directory_item_{self.fields_size}_{self.annotated_methods_size}_{self.annotated_parameters_size}"}
        for field_annotation in self.field_annotations:
            structure[field_annotation.name] = field_annotation.to_data_type()
        for method_annotation in self.method_annotations:
            structure[method_annotation.name] = method_annotation.to_data_type()
        for parameter_annotation in self.parameter_annotations:
            structure[parameter_annotation.name] = parameter_annotation.to_data_type()

        return structure
