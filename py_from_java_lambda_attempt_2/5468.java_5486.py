Here is the translation of the Java code into equivalent Python:

```Python
class BrowserCodeUnitFormatOptions:
    def __init__(self, field_options: dict, auto_update: bool):
        self.field_options = field_options
        self.display_options = OptionsBasedDataTypeDisplayOptions(field_options)

        if not self.field_options.get('NAMESPACE_OPTIONS'):
            self.field_options['NAMESPACE_OPTIONS'] = {
                'type': OptionType.CUSTOM_TYPE,
                'option': NamespaceWrappedOption(),
                'description': NAMESPACE_OPTIONS_DESCRIPTIONS,
                'editor': NamespacePropertyEditor()
            }
            HelpLocation(hl="CodeBrowserPlugin", "Operands_Field")
            self.field_options.register_option(
                GhidraOptions.SHOW_BLOCK_NAME_OPTION, False)
            self.field_options.register_option(
                REGISTER_VARIABLE_MARKUP_OPTION, True)
            # ... register other options ...

        if auto_update:
            self.field_options.add_options_listener(self)

    def options_changed(self, field_options: dict, option_name: str, old_value: any, new_value: any):
        if (option_name == GhidraOptions.SHOW_BLOCK_NAME_OPTION or
                option_name in [REGISTER_VARIABLE_MARKUP_OPTION,
                                STACK_VARIABLE_MARKUP_OPTION,
                                INFERRED_VARIABLE_MARKUP_OPTION,
                                ALWAYS_SHOW_PRIMARY_REFERENCE_MARKUP_OPTION,
                                FOLLOW_POINTER_REFERENCE_MARKUP_OPTION]):
            self.update_format()
            self.notify_listeners()

    def update_format(self):
        namespace_option = self.field_options['NAMESPACE_OPTIONS']
        show_block_name = self.field_options.get(
            GhidraOptions.SHOW_BLOCK_NAME_OPTION, False)
        show_namespace = CodeUnitFormatOptions.ShowNamespace.NEVER
        local_prefix_override = None

        if namespace_option.is_show_local_namespace():
            if namespace_option.is_show_non_local_namespace():
                show_namespace = CodeUnitFormatOptions.ShowNamespace.ALWAYS
            else:
                show_namespace = CodeUnitFormatOptions.ShowNamespace.LOCAL
            if namespace_option.use_local_prefix_override():
                local_prefix_override = (
                    namespace_option.get_local_prefix_text().strip())
        elif namespace_option.show_non_local_namespace():
            show_namespace = CodeUnitFormatOptions.ShowNamespace.NON_LOCAL

        self.field_options['SHOW_NAMESPACE'] = show_namespace
        self.local_prefix_override = local_prefix_override

    def add_change_listener(self, listener):
        self.listeners.add(listener)

    def remove_change_listener(self, listener):
        self.listeners.remove(listener)

    def notify_listeners(self):
        event = ChangeEvent(self)
        SwingUtilities.invokeLater(lambda: [listener.state_changed(event) for listener in self.listeners])

    @property
    def follow_referenced_pointers(self):
        return self.follow_referenced_pointers

class OptionsBasedDataTypeDisplayOptions:
    pass

class NamespaceWrappedOption:
    pass

class NamespacePropertyEditor:
    pass

class CodeUnitFormatOptions:
    ShowNamespace = {'NEVER': 0, 'LOCAL': 1, 'ALWAYS': 2}

# ... other classes and functions ...
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect as there might be some differences in how certain concepts are handled between the two languages.