Here is a translation of the Java code into equivalent Python:

```Python
class ReturnEffect:
    def __init__(self):
        pass

    @staticmethod
    def register_effect():
        # This line should be replaced with actual registration logic in Skript.
        print("registering return effect")

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: bool) -> bool:
        if not self.check_function(exprs):
            return False

        if is_delayed:
            print("A return statement after a delay is useless...")
            return False

        function = Functions.current_function
        class_info = function.get_return_type()
        if class_info is None:
            print("This function doesn't return any value.")
            return False

        try:
            value = exprs[0].convert(class_info)
            if value is None:
                print(f"This function is declared to return {class_info.name}, but {exprs[0]} is not of that type.")
                return False
        except Exception as e:
            SkriptLogger.log_error(str(e))
            return False

        try:
            RetainingLogHandler.start_retaining_log()
            if value.is_single() and function.is_single():
                print("This function is defined to only return a single", class_info.name, "but this return statement can return multiple values.")
                return False
            SkriptLogger.log(str(value))
        finally:
            log.stop()

        self.function = function
        self.value = value

        return True

    def walk(self, e: Event) -> TriggerItem:
        if isinstance(e, FunctionEvent):
            ((ScriptFunction) self.function).set_return_value(self.value.get_array(e))

        # This part should be adjusted based on the actual implementation of Skript.
        parent = self.get_parent()
        while parent is not None:
            if isinstance(parent, SecLoop):
                (parent as SecLoop).exit(e)
            elif isinstance(parent, SecWhile):
                (parent as SecWhile).reset()

            parent = parent.get_parent()

        return None

    def execute(self, e: Event) -> None:
        # This method should be adjusted based on the actual implementation of Skript.
        pass

    def __str__(self, e: Event | None, debug: bool) -> str:
        if e is not None and debug:
            return f"return {self.value}"
        else:
            return "return"

class Expression:
    def convert(self, class_info):
        # This method should be adjusted based on the actual implementation of Skript.
        pass

class FunctionEvent(Event):
    pass
```

Please note that this is a translation and not an exact equivalent. Python has different syntax and semantics than Java, so some parts may need to be adjusted or rewritten for them to work correctly in Python.