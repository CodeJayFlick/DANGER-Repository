Here is the equivalent Python code:

```Python
class SymbolTreeDataFlavor:
    _JAVA_CLASS_NAME = "SymbolTreeNode"
    DATA_FLAVOR = f"application/x-symbol-tree-node; class={_JAVA_CLASS_NAME}"

    def __init__(self, display_text):
        super().__init__(DATA_FLAVOR, display_text)
```

Note that Python does not have a direct equivalent to Java's `DataFlavor` or `GenericDataFlavor`. The above code creates a custom class `SymbolTreeDataFlavor` with an attribute `_JAVA_CLASS_NAME` and another attribute `DATA_FLAVOR`, which is used in the constructor.