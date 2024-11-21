class DataModelNameBinderImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # Equivalent to OpaqueCleanable in Java
        self.jna_data = jna_data
        self.value = None
        self.metadata = None
        self.reference = None

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def bind_value(self, context_object, name):
        p_context_object = context_object.pointer()
        pp_value = PointerByReference()
        pp_metadata = PointerByReference()
        jna_data.BindValue(p_context_object, name, pp_value, pp_metadata)
        
        try:
            self.value = ModelObjectInternal.try_preferred_interfaces(pp_value.get_value())
        finally:
            pp_value.release()

        try:
            self.metadata = KeyStoreInternal.try_preferred_interfaces(pp_metadata.get_value())
        finally:
            pp_metadata.release()

    def bind_reference(self, context_object, name):
        p_context_object = context_object.pointer()
        pp_reference = PointerByReference()
        pp_metadata = PointerByReference()
        jna_data.BindReference(p_context_object, name, pp_reference, pp_metadata)
        
        try:
            self.reference = ModelObjectInternal.try_preferred_interfaces(pp_reference.get_value())
        finally:
            pp_reference.release()

        try:
            self.metadata = KeyStoreInternal.try_preferred_interfaces(pp_metadata.get_value())
        finally:
            pp_metadata.release()

    def enumerate_values(self, context_object):
        p_context_object = context_object.pointer()
        pp_enumerator = PointerByReference()
        jna_data.EnumerateValues(p_context_object, pp_enumerator)
        
        try:
            return KeyEnumeratorInternal.try_preferred_interfaces(pp_enumerator.get_value())
        finally:
            pp_enumerator.release()

    def enumerate_references(self, context_object):
        p_context_object = context_object.pointer()
        pp_enumerator = PointerByReference()
        jna_data.EnumerateReferences(p_context_object, pp_enumerator)
        
        try:
            return KeyEnumeratorInternal.try_preferred_interfaces(pp_enumerator.get_value())
        finally:
            pp_enumerator.release()

    def get_value(self):
        return self.value

    def get_metadata(self):
        return self.metadata

    def get_reference(self):
        return self.reference
