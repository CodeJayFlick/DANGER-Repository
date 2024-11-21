Here is the translation of the Java code to Python:
```
class ClangLabelToken:
    def __init__(self):
        self.blockaddr = None  # Address this is labelling

    def is_variable_ref(self) -> bool:
        return False

    def get_min_address(self) -> 'Address':
        return self.blockaddr

    def get_max_address(self) -> 'Address':
        return self.blockaddr

    def restore_from_xml(self, el: dict, end: dict, pfactory: object):
        super().restore_from_xml(el, end, pfactory)
        name = el['attribute']['ClangXML_SPACE']
        spc = pfactory.get_address_factory().get_address_space(name)
        offset = SpecXmlUtils.decode_long(el['attribute']['ClangXML_OFFSET'])
        self.blockaddr = spc.get_address(offset)

class Address:
    pass

class PcodeFactory:
    def get_address_factory(self) -> object:
        return None  # Replace with actual implementation
```
Note that I had to make some assumptions about the Python types and classes, as they were not explicitly defined in the Java code. Specifically:

* `Address` is a class representing an address, which was missing from the original Java code.
* `PcodeFactory` is another class providing methods for working with addresses, which also needed to be implemented.

In reality, these classes would likely require more complex implementations depending on your specific use case and requirements.