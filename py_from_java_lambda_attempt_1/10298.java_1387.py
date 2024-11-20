Here is the translation of the Java code to Python:
```
class EditorStateFactory:
    cache = {}

    def __init__(self):
        pass

    def get_editor_state(self, options, name, listener):
        option_id = options.get_id(name)
        editor_state = self.cache.get(option_id)
        if editor_state is None:
            editor_state = EditorState(options, name)
            self.cache[option_id] = editor_state
        editor_state.add_listener(listener)  # this class uses a set to avoid duplicate listeners
        return editor_state

    def clear(self, options, name):
        del self.cache[options.get_id(name)]

    def clear_all(self):
        self.cache.clear()
```
Note that I've used the following Python concepts:

* Classes and objects: `EditorStateFactory` is a class with an empty constructor (`__init__`) and methods.
* Dictionaries (hash maps): The `cache` dictionary stores key-value pairs, where keys are strings and values are `EditorState` objects.
* String manipulation: I've used the `.get_id()` method to retrieve a string ID from the `options` object, and then looked up or set an entry in the cache using that ID as the key.
* Object creation: The `EditorState` class is not defined here (it would need its own implementation), but you can imagine it being created with the given options and name.

Let me know if this translation meets your requirements!