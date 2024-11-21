Here is the translation of the Java code to Python:

```
class GraphPluginPackage:
    NAME = "Graph"

    def __init__(self):
        super().__init__(NAME, ResourceManager.load_image("images/katomic.png"),
                         "Provides plugins that display information in graph form.")

# Note: In Python, we don't have a direct equivalent of Java's package declaration.
# Instead, you can use modules or classes to organize your code.