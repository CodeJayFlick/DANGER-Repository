import os

class NamespaceCategoryNode:
    OPEN_FOLDER_NAMESPACES_ICON = None
    CLOSED_FOlDER_NAMESPACES_ICON = None

    def __init__(self, program):
        super().__init__(SymbolCategory.NAMESPACE_CATEGORY, program)

    def get_icon(self, expanded):
        return self.OPEN_FOLDER_NAMESPACES_ICON if expanded else self.CLOSED_FOLDER_NAMESPACES_ICON

    def supports_symbol(self, symbol):
        if super().supports_symbol(symbol):
            return True
        parent_namespace = symbol.get_parent_namespace()
        return parent_namespace is not None and parent_namespace != 'globalNamespace'

    def supports_data_flavors(self, data_flavors):
        for flavor in data_flavors:
            if self.is_supported_local_flavor(flavor):
                return True
        return False

    def is_supported_local_flavor(self, flavor):
        if not self.is_local_data_flavor(flavor):
            return False
        return flavor != 'ClassSymbolNode.LOCAL_DATA_FLAVOR'

# Note: The following methods are missing in the given Java code:
# - super()
# - SymbolCategory.NAMESPACE_CATEGORY
# - program.get_parent_namespace()
# - ClassSymbolNode.LOCAL_DATA_FLAVOR

class ResourceManager:
    @staticmethod
    def load_image(image_path):
        return None  # Assuming this method returns an image object, replace with actual implementation.

if __name__ == "__main__":
    class SymbolCategory:
        NAMESPACE_CATEGORY = 'NAMESPACE_CATEGORY'

    class Program:
        def get_parent_namespace(self):
            pass

    class Namespace:
        @staticmethod
        def getParentNamespace():
            return None  # Assuming this method returns the parent namespace, replace with actual implementation.

    class DataFlavor:
        pass

    class ClassSymbolNode:
        LOCAL_DATA_FLAVOR = 'LOCAL_DATA_FLAVOR'

    program = Program()
    node = NamespaceCategoryNode(program)
