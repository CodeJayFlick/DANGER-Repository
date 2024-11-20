Here is the translation of the given Java code into Python:

```Python
class LocationClangHighlightController:
    def field_location_changed(self, location: 'FieldLocation', field: 'Field', trigger: 'EventTrigger') -> None:
        self.clear_primary_highlights()
        
        if not isinstance(field, ClangTextField):
            return
        
        token = ((ClangTextField)field).get_token(location)
        if token is None:
            return
        
        self.add_primary_highlight(token, default_highlight_color)
        if isinstance(token, ClangSyntaxToken):
            self.add_primary_highlight_to_tokens_for_parenthesis((ClangSyntaxToken)token, default_paren_color)
            self.add_highlight_brace((ClangSyntaxToken)token, default_paren_color)

    def clear_primary_highlights(self) -> None:
        pass

    def add_primary_highlight(self, token: 'ClangToken', color: str) -> None:
        pass

    def add_primary_highlight_to_tokens_for_parenthesis(self, token: 'ClangSyntaxToken', color: str) -> None:
        pass

    def add_highlight_brace(self, token: 'ClangSyntaxToken', color: str) -> None:
        pass
```

Please note that Python does not support the exact equivalent of Java's `@Override` annotation. Also, in Python, you don't need to specify types for function parameters or return values unless you want to use type hints (which are optional).