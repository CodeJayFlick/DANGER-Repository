class DefaultOptionComponent:
    def __init__(self, editor_state):
        self.component = None
        self.label = None
        
        super().__init__()
        
        layout = PairLayout(0, 6, 40)
        set_layout(layout)

        if isinstance(editor_state.get_editor_component(), AbstractButton):
            label_mouse_listener = MouseAdapter()
            def mouse_pressed(event):
                if not component.isEnabled():
                    return
                button = (AbstractButton)component
                button.set_selected(not button.is_selected())
            
            label_mouse_listener.mouse_pressed = mouse_pressed
            
            self.label.addMouseListener(label_mouse_listener)
        
        set_size(get_preferred_size())

        description = editor_state.get_description()
        if description is not None:
            html_description = HTMLUtilities.to_wrapped_html(description)
            self.label.set_tooltip_text(html_description)

            if isinstance(component, JComponent):
                component.set_tooltip_text(html_description)
            
            add(self.label)
            add(component)

    def set_enabled(self, enabled):
        self.label.setEnabled(enabled)
        self.component.setEnabled(enabled)

    def set_alignment_preferred_size(self, dimension):
        self.label.set_preferred_size(dimension)

    def get_preferred_alignment_size(self):
        preferred_size = self.label.get_preferred_size()
        
        max_height = max(preferred_size.height, component.get_preferred_size().height)
        return Dimension(preferred_size.width, max_height)
