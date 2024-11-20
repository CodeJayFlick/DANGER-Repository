Here is a translation of the Java code into equivalent Python code:

```Python
class SvgPackage:
    def __init__(self):
        pass

    def create_view_managers(self, react_context):
        return [
            GroupViewManager(),
            PathViewManager(),
            CircleViewManager(),
            EllipseViewManager(),
            LineViewManager(),
            RectViewManager(),
            TextViewManager(),
            TSpanViewManager(),
            TextPathViewManager(),
            ImageViewManager(),
            ClipPathViewManager(),
            DefsViewManager(),
            UseViewManager(),
            SymbolManager(),
            LinearGradientManager(),
            RadialGradientManager(),
            PatternManager(),
            MaskManager(),
            ForeignObjectManager(),
            MarkerManager(),
            SvgViewManager()
        ]

    def create_native_modules(self, react_context):
        return [
            SvgViewModule(react_context),
            RNSVGRenderableManager(react_context)
        ]

    def create_js_modules(self):
        return []
```

Please note that this is a direct translation of the Java code into Python. However, there are some differences between the two languages:

1. In Java, you need to explicitly specify the type of variables and method parameters using keywords like `int`, `String`, etc., whereas in Python, variable types are inferred by the interpreter.

2. The concept of null is not present in Python as it is in Java. Instead, Python has a special value called None which can be used when you want to represent an object that doesn't exist or hasn't been initialized yet.

3. In Java, there's no direct equivalent for Python's list comprehension feature. However, the code I provided does use this feature to create lists of view managers and native modules in one line each.

4. The `@Nonnull` annotation is not present in Python as it is in Java.