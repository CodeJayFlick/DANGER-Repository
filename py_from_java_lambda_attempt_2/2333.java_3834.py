Here is the translation of the Java code to Python:
```
class TraceAddressFactory:
    def __init__(self, language, compiler_spec):
        super().__init__(language, compiler_spec)

    def add_overlay_address_space(self, name: str, preserve_name: bool,
                                    original_space: 'AddressSpace', min_offset: int, max_offset: int) -> 'OverlayAddressSpace':
        return super().add_overlay_address_space(name, preserve_name, original_space, min_offset, max_offset)

    def add_overlay_address_space(self, ov_space: 'OverlayAddressSpace') -> None:
        try:
            super().add_overlay_address_space(ov_space)
        except DuplicateNameException as e:
            raise

    def remove_overlay_space(self, name: str) -> None:
        return super().remove_overlay_space(name)

class AddressSpace:
    pass

class OverlayAddressSpace(AddressSpace):
    pass
```
Note that I've used Python's type hinting system to indicate the types of variables and method parameters. This is not strictly necessary for a working program, but it can be helpful for documentation and static analysis.

Also, I've kept the `super()` calls as they are in the original Java code, assuming that you want to maintain compatibility with any existing Java code or libraries that might be using these methods. If you're writing pure Python code without direct interaction with Java classes, you could simplify the method implementations by removing the `super()` calls and just implementing the desired behavior directly.

Finally, I've defined two additional classes (`AddressSpace` and `OverlayAddressSpace`) to represent the types of objects that are being manipulated in this code. These classes don't have any specific implementation or methods beyond what's required for type hinting purposes.