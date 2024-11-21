Here's your translated code in Python:

```Python
class CompletelyDifferentHTMLDataTypeRepresentationWrapper:
    def __init__(self, wrapped_representation):
        super().__init__(wrapped_representation.original_html_data)

    def get_html_string(self):
        return f"<{self.get_html_content_string()}>"

    def get_html_content_string(self):
        return self.get_html_content_string()

    def diff(self, other_representation):
        if not isinstance(other_representation, CompletelyDifferentHTMLDataTypeRepresentationWrapper):
            return [this, CompletelyDifferentHTMLDataTypeRepresentationWrapper(other_representation)]
        
        # this is already completely different, so no work needs to be done
        return [self, other_representation]
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. It also doesn't support multiple inheritance like Java (although it can simulate it using interfaces and mixins).