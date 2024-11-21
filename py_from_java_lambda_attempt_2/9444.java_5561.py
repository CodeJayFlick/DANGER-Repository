Here is the translation of the Java code into Python:

```Python
class GenericOptionsComponent:
    def __init__(self, editor_state):
        self.editor_state = editor_state

    @staticmethod
    def create_option_component(editor_state):
        if editor_state.supports_custom_options_editor():
            return CustomOptionComponent(editor_state)
        else:
            return DefaultOptionComponent(editor_state)

    @staticmethod
    def align_labels(components):
        max_width = 0
        max_height = 0
        for component in components:
            dimension = component.get_preferred_alignment_size()
            max_width = max(max_width, dimension.width)
            max_height = max(max_height, dimension.height)

        for component in components:
            component.set_alignment_preferred_size((max_width, max_height))

    def set_enabled(self, enabled):
        pass

    def set_alignment_preferred_size(self, size):
        pass

    def get_preferred_alignment_size(self):
        return self.get_preferred_size()

class CustomOptionComponent(GenericOptionsComponent):
    pass

class DefaultOptionComponent(GenericOptionsComponent):
    pass
```

Please note that Python does not have direct equivalent of Java's `JPanel` and other Swing components. Also, the code assumes that there are separate classes for custom and default option components which is similar to how it was structured in the original Java code.