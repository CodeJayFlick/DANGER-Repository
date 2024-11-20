Here is the translation of the Java code into Python:

```Python
class IntegerSpinner:
    def __init__(self, spinner_model):
        self.spinner = JSpinner(spinner_model)
        self.integer_text_field = IntegerTextField(10, int(spinner_model.get_value()))
        self.integer_text_field.component().set_name("integer.spinner.editor")
        max_val = spinner_model.get_maximum()
        if max_val is not None:
            self.integer_text_field.set_max_value(int(max_val))
        
        self.spinner.set_editor(self.integer_text_field.component())
        
        def on_spinner_change(event):
            new_val = int(spinner_model.get_value())
            self.integer_text_field.set_value(new_val)
        
        spinner_model.addChangeListener(on_spinner_change)

        def on_key_press(event):
            if event.keycode == 38:  # up
                new_val = int(spinner_model.next_value())
            elif event.keycode == 40:  # down
                new_val = int(spinner_model.previous_value())
            else:
                return
            
            self.spinner.set_value(new_val)
        
        self.integer_text_field.component().add_key_listener(on_key_press)

        def on_mouse_wheel(event):
            if event.get_rotation() > 0:
                prev_val = spinner_model.previous_value()
                if prev_val is not None:
                    self.spinner.set_value(prev_val)
            else:
                next_val = spinner_model.next_value()
                if next_val is not None:
                    self.spinner.set_value(next_val)

        self.spinner.add_mouse_wheel_listener(on_mouse_wheel)

        def on_text_field_change(event):
            value = int(self.integer_text_field.get_value())
            if value is not None:
                self.spinner.set_value(value)
        
        self.integer_text_field.addChangeListener(on_text_field_change)

    @property
    def spinner(self):
        return self._spinner

    @property
    def text_field(self):
        return self._integer_text_field

    def set_value(self, value):
        self.spinner.set_value(value)
        self.integer_text_field.set_value(int(value))
        
        for listener in self.change_listeners:
            listener.state_changed()
    
    def add_change_listener(self, listener):
        if not hasattr(self, 'change_listeners'):
            self.change_listeners = []
        self.change_listeners.append(listener)

    def remove_change_listener(self, listener):
        try:
            self.change_listeners.remove(listener)
        except ValueError:
            pass

    def fire_state_changed(self):
        for listener in self.change_listeners:
            listener.state_changed()
```

Note: This code is not exactly equivalent to the Java code. The Python version does not include all of the same functionality, and some parts have been simplified or modified to work with Python's syntax and semantics.