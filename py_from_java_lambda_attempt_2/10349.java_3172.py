Here is the translation of the given Java code into Python:

```Python
class CascadedDropTarget:
    def __init__(self, comp, first_drop_target, second_drop_target):
        if not (first_drop_target or second_drop_target):
            raise ValueError("Drop targets may not be null")
        
        self.primary_drop_target = first_drop_target
        self.secondary_drop_target = second_drop_target

    def drop(self, dtde):
        clear_autoscroll()
        if not hasattr(self, 'active_drop_target'):
            dtde.reject_drop()
            return
        
        self.active_drop_target.drop(dtde)

    def drag_enter(self, dtde):
        initialize_autoscrolling(dtde.get_location())
        event_wrapper = DropTargetDragEventWrapper(dtde)
        self.primary_drop_target.drag_enter(event_wrapper)
        
        if not event_wrapper.is_accepted():
            self.active_drop_target = self.secondary_drop_target
            self.secondary_drop_target.drag_enter(event_wrapper)

    def drag_over(self, dtde):
        update_autoscroll(dtde.get_location())
        
        if not hasattr(self, 'active_drop_target'):
            event_wrapper = DropTargetDragEventWrapper(dtde)
            self.primary_drop_target.drag_over(event_wrapper)
            
            if not event_wrapper.is_accepted():
                self.active_drop_target = self.secondary_drop_target
                self.secondary_drop_target.drag_over(event_wrapper)

    def drop_action_changed(self, dtde):
        update_autoscroll(dtde.get_location())
        
        if hasattr(self, 'active_drop_target'):
            self.active_drop_target.drop_action_changed(dtde)
            
    def drag_exit(self, dte):
        clear_autoscroll()
        self.primary_drop_target.drag_exit(dte)
        self.secondary_drop_target.drag_exit(dte)

class DropTargetDragEventWrapper:
    def __init__(self, original_event):
        super().__init__()
        self.original_event = original_event
        self.is_accepted = False
        self.drag_operation = None
        self.is_rejected = False

    def accept_drag(self, drag_op):
        self.is_accepted = True
        self.drag_operation = drag_op

    def reject_drag(self):
        self.is_rejected = True

    @property
    def is_accepted(self):
        return self._is_accepted

    @is_accepted.setter
    def is_accepted(self, value):
        self._is_accepted = value

    def flush(self):
        if self.is_accepted:
            self.original_event.accept_drag(self.drag_operation)
        elif self.is_rejected:
            self.original_event.reject_drag()
```

Please note that Python does not have direct equivalent of Java's `synchronized` keyword. It is used to ensure thread safety in multi-threaded environment, but it can be achieved using locks or other synchronization primitives in Python.

Also, the concept of "clearAutoscroll", "initializeAutoscrolling" and "updateAutoscroll" are not present in this translation as they seem to be specific to Java's AWT (Abstract Window Toolkit) which is not directly equivalent to Python.