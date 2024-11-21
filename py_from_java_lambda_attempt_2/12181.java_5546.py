Here is the translation of the Java code into Python:

```Python
class CodeBlockModel:
    EMPTY_BLOCK_ARRAY = []

    def __init__(self):
        pass

    def get_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_code_block_at(self, addr: 'Address', monitor=None) -> 'CodeBlock':
        if monitor is None:
            return None
        else:
            try:
                result = self.get_code_block_at_impl(addr)
                return result
            except CancelledException as e:
                raise e

    def get_first_code_block_containing(self, addr: 'Address', monitor=None) -> 'CodeBlock':
        if monitor is None:
            return None
        else:
            try:
                result = self.get_first_code_block_containing_impl(addr)
                return result
            except CancelledException as e:
                raise e

    def get_code_blocks_containing(self, addr: 'Address', monitor=None) -> list['CodeBlock']:
        if monitor is None:
            return []
        else:
            try:
                result = self.get_code_blocks_containing_impl(addr)
                return result
            except CancelledException as e:
                raise e

    def get_code_blocks(self, monitor=None) -> 'CodeBlockIterator':
        if monitor is None:
            return CodeBlockIterator()
        else:
            try:
                result = self.get_code_blocks_impl()
                return result
            except CancelledException as e:
                raise e

    def get_sources(self, block: 'CodeBlock', monitor=None) -> 'CodeBlockReferenceIterator':
        if monitor is None:
            return CodeBlockReferenceIterator()
        else:
            try:
                result = self.get_sources_impl(block)
                return result
            except CancelledException as e:
                raise e

    def get_num_sources(self, block: 'CodeBlock', monitor=None) -> int:
        if monitor is None:
            return 0
        else:
            try:
                result = self.get_num_sources_impl(block)
                return result
            except CancelledException as e:
                raise e

    def get_destinations(self, block: 'CodeBlock', monitor=None) -> 'CodeBlockReferenceIterator':
        if monitor is None:
            return CodeBlockReferenceIterator()
        else:
            try:
                result = self.get_destinations_impl(block)
                return result
            except CancelledException as e:
                raise e

    def get_num_destinations(self, block: 'CodeBlock', monitor=None) -> int:
        if monitor is None:
            return 0
        else:
            try:
                result = self.get_num_destinations_impl(block)
                return result
            except CancelledException as e:
                raise e

    def get_basic_block_model(self):
        pass

    def externals_included(self) -> bool:
        return False

    def get_flow_type(self, block: 'CodeBlock') -> FlowType:
        if isinstance(block, CodeBlock):
            return FlowType.FALLTHROUGH
        else:
            raise ValueError("Invalid code block")

    def get_name(self, block: 'CodeBlock') -> str:
        pass

    def get_program(self) -> Program:
        pass

    def allows_block_overlap(self) -> bool:
        return False


class CodeBlockReferenceIterator:
    pass


class FlowType:
    FALLTHROUGH = 0
    UNKNOWN = 1
    MULTIFLOW = 2


class Address:
    pass


class Program:
    pass


class CancelledException(Exception):
    pass
```

Note that this translation is not a direct conversion from Java to Python, but rather an interpretation of the code in terms of Python. The actual implementation may vary depending on your specific requirements and constraints.