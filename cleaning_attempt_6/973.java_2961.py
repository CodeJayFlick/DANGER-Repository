class DynamicKeyProviderConceptImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # Assuming this can be set later in your program
        self.jna_data = jna_data
        self.key_value = None
        self.metadata = None

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def get_key(self, context_object, key):
        p_context_object = context_object.pointer()
        pp_key_value = PointerByReference()
        pp_metadata = PointerByReference()
        p_has_key = BOOLByReference()
        jna_data.GetKey(p_context_object, key, pp_key_value, pp_metadata, p_has_key)
        self.key_value = ModelObjectImpl.get_object_with_metadata(pp_key_value.value, pp_metadata.value)
        return p_has_key.value

    def set_key(self, context_object, key, key_value, concept_metadata):
        p_context_object = context_object.pointer()
        p_key_value = key_value.pointer()
        p_metadata = concept_metadata.pointer()
        jna_data.SetKey(p_context_object, key, p_key_value, p_metadata)

    def enumerate_keys(self, context_object):
        p_context_object = context_object.pointer()
        pp_enumerator = PointerByReference()
        jna_data.EnumerateKeys(p_context_object, pp_enumerator)
        wrap = WrapIKeyEnumerator(pp_enumerator.value)
        return KeyEnumeratorInternal.try_preferred_interfaces(wrap.QueryInterface)

    def get_key_value(self):
        return self.key_value

    def set_metadata(self, metdata):
        self.metadata = metdata
