Here is the translation of the Java code into Python:

```Python
from comtypes import *

class DataModelManagerImpl1:
    def __init__(self, jna_data):
        self.cleanable = DbgModel.release_when_phantom(self, jna_data)
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def close(self):
        COMUtils.check_rc(self.jna_data.close())

    def create_no_value(self):
        pp_context_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_no_value(pp_context_object))
        
        wrap = WrapIModelObject(pp_context_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_error_object(self, hr_error, pwsz_message):
        pp_context_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_error_object(hr_error, pwsz_message, pp_context_object))
        
        wrap = WrapIModelObject(pp_context_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_typed_object(self, context, object_location, object_type):
        p_context = context.get_pointer()
        p_object_type = object_type.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_typed_object(p_context, object_location, p_object_type, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_typed_object_reference(self, context, object_location, object_type):
        p_context = context.get_pointer()
        p_object_type = context.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_typed_object_reference(p_context, object_location, p_object_type, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_synthetic_object(self, context):
        p_context = context.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_synthetic_object(p_context, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_data_model_object(self, data_model):
        p_data_model = data_model.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_data_model_object(p_data_model, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_intrinsic_object(self, object_kind, intrinsic_data):
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_intrinsic_object(object_kind, intrinsic_data, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def create_typed_intrinsic_object(self, intrinsic_data, object_type):
        p_object_type = object_type.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_typed_intrinsic_object(intrinsic_data, p_object_type, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_model_for_type_signature(self, type_signature):
        p_type_signature = type_signature.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_model_for_type_signature(p_type_signature, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_model_for_type(self, object_type):
        p_object_type = object_type.get_pointer()
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_model_for_type(p_object_type, pp_object))
        
        type_signature = DebugHostTypeSignatureInternal.try_preferred_interfaces(wrap.query_interface())
        wildcard_matches = DebugHostSymbolEnumeratorInternal.try_preferred_interfaces(wrap1.query_interface())

    def register_model_for_type_signature(self, type_signature, data_model):
        p_type_signature = type_signature.get_pointer()
        COMUtils.check_rc(self.jna_data.register_model_for_type_signature(p_type_signature, data_model))

    def unregister_model_for_type_signature(self, data_model, type_signature):
        COMUtils.check_rc(self.jna_data.unregister_model_for_type_signature(data_model, type_signature))

    def register_extension_for_type_signature(self, type_signature, data_model):
        p_type_signature = type_signature.get_pointer()
        COMUtils.check_rc(self.jna_data.register_extension_for_type_signature(p_type_signature, data_model))

    def unregister_extension_for_type_signature(self, data_model, type_signature):
        COMUtils.check_rc(self.jna_data.unregister_extension_for_type_signature(data_model, type_signature))

    def create_metadata_store(self, parent_store):
        p_parent_store = parent_store.get_pointer()
        pp_metadata_store = PointerByReference()
        COMUtils.check_rc(self.jna_data.create_metadata_store(p_parent_store, pp_metadata_store))
        
        wrap = WrapIKeyStore(pp_metadata_store.value)
        try:
            return KeyStoreInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_root_namespace(self):
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.get_root_namespace(pp_object))
        
        value = pp_object.value
        if value is None:
            return None
        
        wrap = WrapIModelObject(value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def register_named_model(self, model_name, data_model):
        COMUtils.check_rc(self.jna_data.register_named_model(model_name, data_model))

    def unregister_named_model(self, model_name):
        COMUtils.check_rc(self.jna_data.unregister_named_model(model_name))

    def acquire_named_model(self, model_name):
        pp_object = PointerByReference()
        COMUtils.check_rc(self.jna_data.acquire_named_model(model_name, pp_object))
        
        wrap = WrapIModelObject(pp_object.value)
        try:
            return ModelObjectInternal.try_preferred_interfaces(wrap.query_interface())
        finally:
            wrap.release()

    def get_type_signature(self):
        return self.type_signature

    def get_wildcard_matches(self):
        return self.wildcard_matches

    def as_script_manager(self):
        return DataModelScriptManagerInternal.try_preferred_interfaces(self.jna_data.query_interface())

type_signature = None
wildcard_matches = None