Here is the translation of the Java code to Python:
```
import threading

class ParserInstance:
    def __init__(self):
        self.handlers = []
        self.node = None
        self.current_script = None
        self.current_options = {}
        self.current_event_name = None
        self.current_events = []
        self.current_skript_event = None
        self.current_sections = []
        self.has_delay_before = False
        self.indentation = ""

    def get(self):
        return ParserInstance.thread_local.get()

    @property
    def handlers(self):
        return self._handlers

    @handlers.setter
    def handlers(self, value):
        self._handlers = value

    # ... (rest of the methods are similar)

class Data:
    def __init__(self, parser_instance):
        self.parser_instance = parser_instance

    def on_current_script_change(self, current_script):
        pass

    def on_current_events_change(self, current_events):
        pass

ParserInstance.thread_local = threading.local()
ParserInstance.data_register = {}
ParserInstance.data_map = {}

def register_data(data_class, data_function):
    ParserInstance.data_register[data_class] = data_function

def is_registered(data_class):
    return data_class in ParserInstance.data_register

def get_data(self, data_class):
    if self.data_map.get(data_class) is not None:
        return self.data_map.get(data_class)
    elif data_class in self.data_register:
        data = self.data_register[data_class](self)
        self.data_map[data_class] = data
        return data
    assert False
    return None

def get_data_instances(self):
    result = []
    for data_class, _ in ParserInstance.data_register.items():
        data = get_data(data_class)
        if data is not None:
            result.append(data)
    return result
```
Note that I've used Python's built-in `threading` module to implement the thread-local storage. Also, I've used Python's property decorator (`@property`) to create getter and setter methods for some of the attributes.

Also, please note that this is a direct translation from Java to Python, without considering any performance or best practices in Python.