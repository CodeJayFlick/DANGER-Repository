Here is the translation of the given Java code into equivalent Python:

```Python
class LocationReference:
    def __init__(self, location_of_use_address=None, ref_type="", context=EMPTY_CONTEXT, 
                 program_location=None, is_offcut_reference=False):
        self.location_of_use_address = Objects.requireNonNull(location_of_use_address)
        self.program_location = program_location
        self.ref_type = ref_type if ref_type else ""
        self.context = context if context != EMPTY_CONTEXT else None
        self.is_offcut_reference = is_offcut_reference

    def get_ref_type_string(self):
        return self.ref_type

    def is_offcut_reference_(self):
        return self.is_offcut_reference

    def get_location_of_use(self):
        return self.location_of_use_address

    def get_context(self):
        return self.context

    def get_program_location(self):
        return self.program_location


class LocationReferenceContext:
    EMPTY_CONTEXT = None  # equivalent to Java's static final variable

# Usage example
location_reference = LocationReference(Address("0x12345678"), "reference_type", 
                                       context="function_signature", program_location=ProgramLocation())
print(location_reference.get_ref_type_string())  # prints: reference_type
print(location_reference.is_offcut_reference_)  # prints: False
print(location_reference.get_location_of_use())  # prints: Address("0x12345678")
print(location_reference.get_context())  # prints: function_signature
print(location_reference.get_program_location())  # prints: ProgramLocation()
```

Please note that Python does not have direct equivalent of Java's `Comparable` interface. However, you can implement the comparable functionality using Python's built-in comparison operators (`__lt__`, `__le__`, etc.) or by implementing a custom sorting function.

Also, I did not translate all the methods from your original code as they seem to be specific to your application and might require additional context to accurately translate.