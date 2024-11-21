Here's the equivalent Python code:

```Python
class ParameterSymbolNode:
    PARAMETER_ICON = None

    def __init__(self, program, symbol):
        super().__init__(program, symbol)

    def get_icon(self, expanded=False):
        return self.PARAMETER_ICON

    def set_node_cut(self, is_cut: bool):
        raise NotImplementedError("Cannot cut a parameter node")

    @property
    def is_leaf(self) -> bool:
        return True


# Example usage:

class ResourceManager:
    @staticmethod
    def load_image(image_name: str):
        # Load the image using your preferred method (e.g., PIL, OpenCV)
        pass

if __name__ == "__main__":
    class Program:
        pass

    class Symbol:
        pass

    resource_manager = ResourceManager()
    program = Program()
    symbol = Symbol()

    node = ParameterSymbolNode(program, symbol)

    print(node.get_icon())  # prints the icon
```

Please note that Python does not have direct equivalents for Java's `Icon` and `ResourceManager`. I've replaced them with a simple placeholder in this example. You would need to implement your own image loading mechanism using libraries like PIL or OpenCV, depending on your requirements.

Also, Python doesn't support static final variables directly; however, you can achieve similar behavior by defining the icon as an instance variable and initializing it only once when creating the first `ParameterSymbolNode` object.