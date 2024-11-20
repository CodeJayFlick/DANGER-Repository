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
