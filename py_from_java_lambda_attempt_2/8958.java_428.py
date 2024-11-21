Here is the translation of the Java interface `VTControllerListener` into a Python class:

```python
class VTControllerListener:
    def session_changed(self, session):
        pass  # implement this method in your subclass

    def match_selected(self, match_info=None):
        pass  # implement this method in your subclass

    def session_updated(self, ev):
        pass  # implement this method in your subclass

    def markup_item_selected(self, markup_item=None):
        pass  # implement this method in your subclass

    def options_changed(self, options):
        pass  # implement this method in your subclass

    def disposed(self):
        pass  # implement this method in your subclass
```

Note that I've kept the same method names and signatures as the original Java interface. In Python, we don't need to declare methods ahead of time like you do with `public` or `void`, so these are just regular instance methods on a class.

If you want to use this class in your own code, you would create a subclass that implements each method according to its specific requirements.