class RuntimeInvisibleAnnotationsAttribute:
    def __init__(self):
        self.numberOf_annotations = None
        self.annotations = []

    def read_from_binary_reader(self, reader):
        super().__init__()
        self.numberOf_annotations = reader.read_short()
        for _ in range(self.get_number_of_annotations()):
            annotation = AnnotationJava(reader)
            self.annotations.append(annotation)

    def get_number_of_annotations(self):
        return self.numberOf_annotations & 0xffff

    def get_annotations(self):
        return self.annotations


class AnnotationJava:
    pass
