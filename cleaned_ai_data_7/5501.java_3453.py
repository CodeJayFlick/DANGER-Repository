class NamespacePropertyEditor:
    DISPLAY_LOCAL_NAMESPACE_LABEL = "Display Local Namespace"
    DISPLAY_NON_LOCAL_NAMESPACE_LABEL = "Display Non-local Namespace"
    LOCAL_NAMESPACE_PREFIX_LABEL = "Local Namespace Prefix"
    DISPLAY_LIBRARY_IN_NAMESPACE_LABEL = "Display library in Namespace"

    NAMES = [DISPLAY_LOCAL_NAMESPACE_LABEL, 
             DISPLAY_NON_LOCAL_NAMESPACE_LABEL,
             LOCAL_NAMESPACE_PREFIX_LABEL, 
             DISPLAY_LIBRARY_IN_NAMESPACE_LABEL]

    SHOW_NON_LOCAL_NAMESPACE_TOOLTIP = f"Prepends namespaces to fields that are not in the local namespace."
    SHOW_LOCAL_NAMESPACE_TOOLTIP = f"Prepends namespaces to fields that are in the local namespace."
    LOCAL_PREFIX_TOOLTIP = f"The prefix value prepended to fields instead of the local namespace of the containing function."
    SHOW_LIBRARY_IN_NAMESPACE_TOOLTIP = "Includes library in namespace when displayed in fields."

    DESCRIPTIONS = [SHOW_LOCAL_NAMESPACE_TOOLTIP, 
                    SHOW_NON_LOCAL_NAMESPACE_TOOLTIP,
                    LOCAL_PREFIX_TOOLTIP, 
                    SHOW_LIBRARY_IN_NAMESPACE_TOOLTIP]

    def __init__(self):
        self.editor_component = self.build_editor()

    def build_editor(self):
        panel = JPanel(VerticalLayout(3))

        show_non_local_checkbox = GCheckBox(DISPLAY_NON_LOCAL_NAMESPACE_LABEL)
        show_non_local_checkbox.setSelected(False)
        show_non_local_checkbox.setToolTipText(SHOW_NON_LOCAL_NAMESPACE_TOOLTIP)

        show_local_checkbox = GCheckBox(DISPLAY_LOCAL_NAMESPACE_LABEL)
        show_local_checkbox.setSelected(False)
        show_local_checkbox.setToolTipText(SHOW_LOCAL_NAMESPACE_TOOLTIP)

        show_library_in_namespace_checkbox = GCheckBox(DISPLAY_LIBRARY_IN_NAMESPACE_LABEL)
        show_library_in_namespace_checkbox.setSelected(True)
        show_library_in_namespace_checkbox.setToolTipText(SHOW_LIBRARY_IN_NAMESPACE_TOOLTIP)

        panel.add(show_non_local_checkbox)
        panel.add(show_library_in_namespace_checkbox)
        panel.add(show_local_checkbox)

        local_prefix_field = self.create_local_prefix_text_field(LOCAL_NAMESPACE_PREFIX_LABEL, 
                                                                  LOCAL_PREFIX_TOOLTIP, 
                                                                  panel)

        show_local_checkbox.addItemListener(lambda e: self.set_local_values(e))
        show_non_local_checkbox.addItemListener(lambda e: self.fire_property_change())
        show_library_in_namespace_checkbox.addItemListener(lambda e: self.fire_property_change())

        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(10, 0, 10, 0), 
            TitledBorder("Namespace Options")))

        return panel

    def create_local_prefix_text_field(self, label_text, tooltip_text, parent):
        text_field = JTextField(20)
        text_field.setEnabled(False)

        text_field_panel = JPanel()
        text_field_panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0))

        use_local_prefix_checkbox = GCheckBox("Use Local Namespace Override")
        use_local_prefix_checkbox.setToolTipText(tooltip_text)
        use_local_prefix_checkbox.addItemListener(lambda e: self.set_local_values(e))
        
        text_field_panel.add(use_local_prefix_checkbox)
        text_field_panel.add(text_field)

        text_field.getDocument().addDocumentListener(DocumentListener(
            lambda event: self.fire_property_change()))

        parent.add(text_field_panel)

        return text_field

    def set_value(self, value):
        if not isinstance(value, NamespaceWrappedOption):
            return
        namespace_option = value
        self.set_local_values(namespace_option)
        self.fire_property_change()

    def set_local_values(self, namespace_option):
        show_non_local_checkbox.setSelected(namespace_option.is_show_non_local_namespace())
        show_local_checkbox.setSelected(namespace_option.is_show_local_namespace())
        show_library_in_namespace_checkbox.setSelected(namespace_option.is_show_library_in_namespace())
        use_local_prefix_checkbox.setSelected(namespace_option.is_use_local_prefix_override())

    def clone_namespace_values(self):
        new_option = NamespaceWrappedOption()
        new_option.set_show_non_local_namespace(show_non_local_checkbox.isSelected())
        new_option.set_show_local_namespace(show_local_checkbox.isSelected())
        new_option.set_show_library_in_namespace(show_library_in_namespace_checkbox.isSelected())
        new_option.set_use_local_prefix_override(use_local_prefix_checkbox.isSelected())

    def get_custom_editor(self):
        return self.editor_component

class NamespaceWrappedOption:
    pass
