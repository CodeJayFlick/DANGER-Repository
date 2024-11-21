Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes.util
from comtypes import COMError, guid
from comtypes.gen import DebugHostSymbolsInternal
from comtypes.client import get_best_interface


class WrapIDebugHostModuleSignature:
    def __init__(self, module_signature):
        self.module_signature = module_signature

    def QueryInterface(self, riid):
        return ctypes.py_object(get_best_interface(self.module_signature))


class WrapIDebugHostTypeSignature:
    def __init__(self, type_signature):
        self.type_signature = type_signature

    def QueryInterface(self, riid):
        return ctypes.py_object(get_best_interface(self.type_signature))


class WrapIDebugHostModule1:
    def __init__(self, module):
        self.module = module

    def QueryInterface(self, riid):
        return ctypes.py_object(get_best_interface(self.module))


class WrapIDebugHostType1:
    def __init__(self, type_):
        self.type_ = type_

    def QueryInterface(self, riid):
        return ctypes.py_object(get_best_interface(self.type_))


class DebugHostSymbolsImpl(DebugHostSymbolsInternal):

    def __init__(self, jna_data):
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def create_module_signature(self, pwsz_module_name, pwsz_min_version, pwsz_max_version):
        module_signature = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.CreateModuleSignature(pwsz_module_name, pwsz_min_version,
                                                     pwsz_max_version, byref(module_signature))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostModuleSignature(module_signature.contents)

    def create_type_signature(self, signature_specification, module=None):
        type_signature = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.CreateTypeSignature(signature_specification,
                                                    module.get_pointer() if module else None,
                                                    byref(type_signature))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostTypeSignature(type_signature.contents)

    def create_type_signature_for_module_range(self, signature_specification, pwsz_module_name,
                                                pwsz_min_version, pwsz_max_version):
        type_signature = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.CreateTypeSignatureForModuleRange(signature_specification,
                                                                 pwsz_module_name, pwsz_min_version,
                                                                 pwsz_max_version, byref(type_signature))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostTypeSignature(type_signature.contents)

    def enumerate_modules(self, context):
        module_enum = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.EnumerateModules(context.get_pointer(), byref(module_enum))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostSymbolEnumerator(module_enum.contents)

    def find_module_by_name(self, context, module_name):
        pp_module = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.FindModuleByName(context.get_pointer(), WString(module_name), byref(pp_module))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostModule1(pp_module.contents)

    def find_module_by_location(self, context, module_location):
        pp_module = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.FindModuleByLocation(context.get_pointer(), module_location,
                                                     byref(pp_module))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostModule1(pp_module.contents)

    def get_most_derived_object(self, context, location, object_type):
        pDerivedLocation = ctypes POINTER(ctypes.c_void_p)
        pp_DerivedType = ctypes POINTER(ctypes.c_void_p)
        result = self.jna_data.GetMostDerivedObject(context.get_pointer(), location,
                                                     object_type.get_pointer(),
                                                     byref(pDerivedLocation), byref(pp_DerivedType))
        if not COMError.checkrc(result):
            raise COMError(result)

        return WrapIDebugHostType1(pp_DerivedType.contents)


class LOCATION:
    def __init__(self, pDerivedLocation):
        self.pDerivedLocation = pDerivedLocation

    @property
    def get_pointer(self):
        return ctypes.c_void_p(self.pDerivedLocation)
```

Please note that this is a translation of the given Java code into equivalent Python.