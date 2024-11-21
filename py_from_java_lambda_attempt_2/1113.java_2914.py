Here is a translation of the Java interface into equivalent Python classes:

```Python
from abc import ABCMeta, abstractmethod

class IDataModelManager1(metaclass=ABCMeta):
    IID_ = "73FE19F4-A110-4500-8ED9-3C28896F508C"

    class VTIndices(enumerate):
        CLOSE = 0
        CREATE_NO_VALUE = 1
        CREATE_ERROR_OBJECT = 2
        CREATE_TYPED_OBJECT = 3
        CREATE_TYPED_OBJECT_REFERENCE = 4
        CREATE_SYNTHETIC_OBJECT = 5
        CREATE_DATA_MODEL_OBJECT = 6
        CREATE_INTRINSIC_OBJECT = 7
        CREATE_TYPED_INTRINSIC_OBJECT = 8
        GET_MODEL_FOR_TYPE_SIGNATURE = 9
        GET_MODEL_FOR_TYPE = 10
        REGISTER_MODEL_FOR_TYPE_SIGNATURE = 11
        UNREGISTER_MODEL_FOR_TYPE_SIGNATURE = 12
        REGISTER_EXTENSION_FOR_TYPE_SIGNATURE = 13
        UNREGISTER_EXTENSION_FOR_TYPE_SIGNATURE = 14
        CREATE_METADATA_STORE = 15
        GET_ROOT_NAMESPACE = 16
        REGISTER_NAMED_MODEL = 17
        UNREGISTER_NAMED_MODEL = 18
        ACQUIRE_NAMED_MODEL = 19

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def create_no_value(self, object=None):
        if object is None:
            return "Error: Object cannot be null"
        else:
            return f"Created no value with object {object}"

    @abstractmethod
    def create_error_object(self, hr_error, message, object=None):
        if object is None:
            return f"Error creating error object. Error code: {hr_error}, Message: {message}"
        else:
            return f"Created error object with error code {hr_error} and message {message}. Object: {object}"

    @abstractmethod
    def create_typed_object(self, context, location, type, object=None):
        if object is None:
            return "Error creating typed object. Context: {}, Location: {}".format(context, location)
        else:
            return f"Created typed object with context {context}, location {location} and type {type}. Object: {object}"

    @abstractmethod
    def create_typed_object_reference(self, context, location, type, object=None):
        if object is None:
            return "Error creating typed object reference. Context: {}, Location: {}".format(context, location)
        else:
            return f"Created typed object reference with context {context}, location {location} and type {type}. Object: {object}"

    @abstractmethod
    def create_synthetic_object(self, context, object=None):
        if object is None:
            return "Error creating synthetic object. Context: {}".format(context)
        else:
            return f"Created synthetic object with context {context}. Object: {object}"

    @abstractmethod
    def create_data_model_object(self, data_model, object=None):
        if object is None:
            return "Error creating data model object. Data Model: {}".format(data_model)
        else:
            return f"Created data model object with data model {data_model}. Object: {object}"

    @abstractmethod
    def create_intrinsic_object(self, kind, intrinsic_data, object=None):
        if object is None:
            return "Error creating intrinsic object. Kind: {}, Intrinsic Data: {}".format(kind, intrinsic_data)
        else:
            return f"Created intrinsic object with kind {kind} and intrinsic data {intrinsic_data}. Object: {object}"

    @abstractmethod
    def create_typed_intrinsic_object(self, intrinsic_data, type, object=None):
        if object is None:
            return "Error creating typed intrinsic object. Intrinsic Data: {}, Type: {}".format(intrinsic_data, type)
        else:
            return f"Created typed intrinsic object with intrinsic data {intrinsic_data} and type {type}. Object: {object}"

    @abstractmethod
    def get_model_for_type_signature(self, type_signature):
        pass

    @abstractmethod
    def get_model_for_type(self, type, data_model=None, type_signature=None, wildcard_matches=None):
        if data_model is None or type_signature is None:
            return "Error getting model for type. Type: {}, Data Model: {}".format(type, data_model)
        elif wildcard_matches is not None:
            return f"Got model for type {type} with data model {data_model}, type signature {type_signature} and wildcard matches {wildcard_matches}"
        else:
            return "Error getting model for type. Type: {}, Data Model: {}".format(type, data_model)

    @abstractmethod
    def register_model_for_type_signature(self, type_signature):
        pass

    @abstractmethod
    def unregister_model_for_type_signature(self, data_model, type_signature):
        pass

    @abstractmethod
    def register_extension_for_type_signature(self, type_signature):
        pass

    @abstractmethod
    def unregister_extension_for_type_signature(self, data_model, type_signature):
        pass

    @abstractmethod
    def create_metadata_store(self, parent_store=None, metadata_store=None):
        if metadata_store is None:
            return "Error creating metadata store. Parent Store: {}".format(parent_store)
        else:
            return f"Created metadata store with parent store {parent_store} and metadata store {metadata_store}"

    @abstractmethod
    def get_root_namespace(self):
        pass

    @abstractmethod
    def register_named_model(self, model_name, model_object=None):
        if model_object is None:
            return "Error registering named model. Model Name: {}".format(model_name)
        else:
            return f"Registered named model {model_name} with object {model_object}"

    @abstractmethod
    def unregister_named_model(self, model_name):
        pass

    @abstractmethod
    def acquire_named_model(self, model_name, model_object=None):
        if model_object is None:
            return "Error acquiring named model. Model Name: {}".format(model_name)
        else:
            return f"Acquired named model {model_name} with object {model_object}"
```

This Python code defines an abstract class `IDataModelManager1` that contains methods for managing data models, such as creating and registering objects, getting root namespaces, etc. The methods are declared using the `@abstractmethod` decorator to indicate they must be implemented by any concrete subclass of this abstract class.

The class also includes a nested enumeration called `VTIndices`, which represents different types of operations that can be performed on data models.