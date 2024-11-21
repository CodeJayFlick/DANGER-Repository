class CodeBlockReference:
    def __init__(self, source: 'CodeBlock', destination: 'CodeBlock', flow_type: str, reference: int, referent: int):
        self.source = source
        self.destination = destination
        self.flow_type = flow_type
        self.reference = reference
        self.referent = referent

    def get_source_block(self) -> 'CodeBlock':
        return self.get_block(self.source, self.destination, self.referent)

    def get_destination_block(self) -> 'CodeBlock':
        return self.get_block(self.destination, self.source, self.reference)

    def get_flow_type(self):
        return self.flow_type

    def get_reference(self):
        return self.reference

    def get_referent(self):
        return self.referent

    def get_source_address(self) -> int:
        block = self.get_source_block()
        if block is not None:
            return block[0]
        else:
            return self.referent

    def get_destination_address(self) -> int:
        block = self.get_destination_block()
        if block is not None:
            return block[0]
        else:
            return self.reference

    def __str__(self):
        return f"{self.referent}  -> {self.reference}"

class CodeBlockReferenceImpl(CodeBlockReference):

    @staticmethod
    def get_block(block_needed: 'CodeBlock', block_have: 'CodeBlock', addr_in_block: int) -> 'CodeBlock':
        if block_needed is None:
            model = block_have.model()
            try:
                block_needed = model.get_first_code_block_containing(addr_in_block, TaskMonitorAdapter.DUMMY_MONITOR)
            except CancelledException as e:
                pass  # can't happen, dummy monitor can't be canceled

            if block_needed is None:  # means that there wasn'nt a good source block there,
                return CodeBlock()  # TODO: This might not be the right thing to do. Return a codeBlock that really isn't there,

        return block_needed
