class EquatableConceptImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # Equivalent to OpaqueCleanable cleanable;
        self.jna_data = jna_data  # IEquatableConcept jnaData;
        self.metadata = None  # KeyStore metadata;

    def get_pointer(self):
        return self.jna_data.get_pointer()  # Pointer getPointer();

    def are_objects_equal(self, context_object, other_object):
        p_context_object = context_object.get_pointer()
        p_other_object = other_object.get_pointer()
        is_equal = None  # BOOLByReference pIsEqual;
        result = self.jna_data.are_objects_equal(p_context_object, p_other_object, is_equal)
        return bool(is_equal) if isinstance(result, int) else False

    def get_metadata(self):
        return self.metadata  # KeyStore getMetadata();

    def set_metadata(self, metadata):
        self.metadata = metadata  # void setMetadata(KeyStore metdata);
