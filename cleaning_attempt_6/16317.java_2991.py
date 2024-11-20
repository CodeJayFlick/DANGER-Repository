class MLPBlockFactory:
    def __init__(self):
        pass

    def new_block(self, model_path: str, arguments: dict) -> object:
        width = int(arguments.get("width", 28))
        height = int(arguments.get("height", 28))
        output = int(arguments.get("output", 10))
        input = width * height
        hidden = list(map(int, arguments.get("hidden", [0])))
        
        return MLP(input, output, hidden)


class MLP:
    def __init__(self, input: int, output: int, hidden: list):
        self.input = input
        self.output = output
        self.hidden = hidden


# Example usage:
mlp_block_factory = MLPBlockFactory()
arguments = {"width": 28, "height": 28, "output": 10, "hidden": [128]}
model_path = ""
block = mlp_block_factory.new_block(model_path, arguments)
print(block)  # prints the created block
