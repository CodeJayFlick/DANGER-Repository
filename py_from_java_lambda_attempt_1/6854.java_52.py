Here is the translation of the Java code into equivalent Python:

```Python
class NullClangHighlightController:
    def field_location_changed(self, location: str, field: dict, trigger: object) -> None:
        pass  # stub

    def get_highlighted_text(self) -> str | None:
        return None

    def add_primary_highlights(
            self,
            parent_node: any,
            color_provider: TokenHighlightColorProvider
    ) -> None:
        pass  # stub

    def add_primary_highlights(
            self,
            parent_node: any,
            ops: set[PcodeOp],
            highlight_color: Color
    ) -> None:
        pass  # stub

    def add_primary_highlights(
            self,
            tokens: Supplier[Collection[ClangToken]],
            highlight_color: Color
    ) -> None:
        pass  # stub

    def clear_all_highlights(self) -> None:
        pass  # stub

    def add_highlight_brace(
            self, token: ClangSyntaxToken, highlight_color: Color
    ) -> None:
        pass  # stub

    def add_listener(self, listener: ClangHighlightListener) -> None:
        pass  # stub

    def remove_listener(self, listener: ClangHighlightListener) -> None:
        pass  # stub
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the `@Override` annotation. Also, Python is dynamically typed and does not require explicit type declarations like Java does.