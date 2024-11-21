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
