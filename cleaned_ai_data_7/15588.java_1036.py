class SequentialBlock:
    def __init__(self):
        self.children = []

    def add(self, block):
        if block is not None:
            self.children.append(block)
        return self

    def add_all(self, blocks):
        for block in blocks:
            self.add(block)
        return self

    def remove_last_block(self):
        if len(self.children) > 0:
            del self.children[-1]

    def replace_last_block(self, block):
        self.remove_last_block()
        if block is not None:
            self.add(block)

    def forward_internal(self, parameter_store, inputs, training=False):
        current = inputs
        for child in self.children:
            current = child.forward(parameter_store, current, training)
        return current

    def initialize_child_blocks(self, manager, data_type, *input_shapes):
        shapes = list(input_shapes)
        for child in self.children:
            child.initialize(manager, data_type, shapes)
            shapes = child.get_output_shapes(shapes)

    def get_output_shapes(self, inputs):
        if not self.children:
            raise ValueError("The sequential block is empty")
        current = list(inputs)
        for child in self.children:
            current = child.get_output_shapes(current)
        return tuple(current)

    def load_metadata(self, load_version, file_like_object):
        if load_version == 2:
            read_input_shapes(file_like_object)
        elif load_version != 1:
            raise MalformedModelException("Unsupported encoding version: " + str(load_version))

    def __str__(self):
        sb = StringBuilder(200)
        sb.append('Sequential(\n')
        for child in self.children:
            block_string = child.__str__().replace("(?m)^", "\t")
            sb.append(block_string).append('\n')
        sb.append(')')
        return str(sb)

class MalformedModelException(Exception):
    pass

def read_input_shapes(file_like_object):
    # Implementation of this method is not provided as it depends on the specific file format
    pass
