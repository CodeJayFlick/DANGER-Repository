class LldbModelTargetFunctionImpl:
    def __init__(self, frame: 'LldbModelTargetStackFrame', function):
        self.frame = frame
        if function.is_valid():
            space = frame.get_model().get_address_space("ram")
            min_addr = space.address(function.start_address.offset)
            max_addr = space.address(function.start_address.offset)

            name = function.name()
            display_name = function.display_name() or name
            mangled_name = function.mangled_name() or name

            prolog_size = function.prologue_byte_size()

            attributes = {
                "Start": min_addr,
                "End": max_addr,
                "Language": str(function.language()),
                "Name": name,
                "Display Name": display_name,
                "Mangled Name": mangled_name,
                "Prolog Size": prolog_size
            }

            self.change_attributes(attributes, "Initialized")

    def get_description(self, level):
        stream = SBStream()
        function = self.frame.get_model().get_object()
        function.description(stream)
        return stream.data

    def get_block_description(self, block: 'SBBlock'):
        stream = SBStream()
        block.description(stream)
        return stream.data


class LldbModelTargetStackFrame:
    pass
