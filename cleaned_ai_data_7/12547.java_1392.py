class FunctionSignatureImpl:
    def __init__(self, name):
        self.name = name

    @property
    def signature(self):
        return self._signature

    @signature.setter
    def signature(self, value):
        self._signature = value

    def __repr__(self):
        return f"FunctionSignatureImpl(name='{self.name}')"

class FunctionDefinitionDataType:
    pass  # No equivalent in Python, just a placeholder for the Java class

def create_function_signature_impl(name: str) -> 'FunctionSignatureImpl':
    """Creates new FunctionSignatureImpl with the given name and default return type"""
    return FunctionSignatureImpl(name)

def create_function_signature_impl_from_signature(signature: object) -> 'FunctionSignatureImpl':
    """Creates new FunctionSignatureImpl based upon an existing function signature"""
    # Note that we don't have a direct equivalent to Java's `super` method in Python
    return FunctionSignatureImpl(signature)

def create_function_definition(function: object, formal_signature=False):
    """
    Create a Function Definition based on a Function.
    The effective signature will be used where forced indirect and auto-params are reflected in the signature.
    """
    # Note that we don't have a direct equivalent to Java's `super` method in Python
    return function

# Example usage:
fs = create_function_signature_impl("my_func")
print(fs)  # Output: FunctionSignatureImpl(name='my_func')
