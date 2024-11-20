Here is the translation of the Java interface `Draggable` into a Python class:

```python
class Draggable:
    def __init__(self):
        pass

    def is_start_drag_ok(self, e):  # equivalent to public boolean isStartDragOk(DragGestureEvent e)
        return True  # or implement your own logic here

    def get_drag_source_listener(self):  # equivalent to public DragSourceListener getDragSourceListener()
        raise NotImplementedError("Method not implemented")

    def move(self):  # equivalent to public void move()
        pass  # or implement your own logic here

    def drag_canceled(self, event):  # equivalent to public void dragCanceled(DragSourceDropEvent event)
        pass  # or implement your own logic here

    def get_drag_action(self):  # equivalent to public int getDragAction()
        return 0  # or implement your own logic here

    def get_transferable(self, p):  # equivalent to public Transferable getTransferable(Point p)
        raise NotImplementedError("Method not implemented")
```

Note that I've used Python's built-in `raise` statement to indicate where the original Java code would have thrown an exception. In a real-world implementation, you'd want to replace these with actual logic or error handling as needed.