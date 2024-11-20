Here is the translation of the Java code into equivalent Python:

```Python
class ParallelBlock:
    def __init__(self):
        self.children = {}
        self.function = None

    def add(self, block: 'Block'):
        if block is not None:
            self.children[block.__class__.__name__] = block
        return self

    def forward(self, parameter_store, inputs, training=False):
        outputs = [block.forward(parameter_store, inputs, training) for block in self.children.values()]
        return self.function(outputs)

    def initialize_child_blocks(self, manager, data_type, input_shapes):
        for child_block in self.children.values():
            child_block.initialize(manager, data_type, input_shapes)

    def get_output_shapes(self, input_shapes):
        if not self.children:
            raise ValueError("The parallel block is empty")

        outputs = []
        for block in self.children.values():
            shapes = block.get_output_shapes(input_shapes)
            output = [manager.create(shape) for shape in shapes]
            outputs.append(output)

        return [output[0].shape for output in outputs]

    def load_metadata(self, load_version: int, is):
        if load_version == 2:
            self.read_input_shapes(is)
        elif load_version != 1:
            raise MalformedModelException(f"Unsupported encoding version: {load_version}")

    def __str__(self):
        sb = StringBuilder(200)
        sb.append("Parallel(\n")
        for block in self.children.values():
            block_string = str(block).replace("(?m)^", "\t").strip()
            sb.append(block_string + '\n')
        sb.append(')')
        return sb.toString()

class MalformedModelException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `abstract class` or `interface`. The above code is a simple translation and might need further modifications based on the actual usage.