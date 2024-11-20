Here is the translation of the given Java code into Python:

```Python
class BurnCookTime:
    def __init__(self):
        self.cook_time = None
        self.is_event = None

    @property
    def cook_time(self):
        return self._cook_time

    @cook_time.setter
    def cook_time(self, value):
        self._cook_time = value

    @property
    def is_event(self):
        return self._is_event

    @is_event.setter
    def is_event(self, value):
        self._is_event = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if isinstance(parse_result.mark, int) and parse_result.mark == 1:
            self.cook_time = True
        else:
            self.cook_time = False
        self.is_event = matched_pattern == 0

    def get(self, e, source):
        if self.is_event:
            return [Timespan.from_ticks(((FurnaceBurnEvent) e).get_burn_time())]
        else:
            result = []
            for block in source:
                if any_furnace.is_type(block):
                    furnace_state = (Furnace)(block.get_state())
                    time = Timespan.from_ticks(cook_time and furnace_state.cook_time or furnace_state.burn_time)
                    result.append(time)
            return result

    def __str__(self, e=None, debug=False):
        if self.is_event:
            return "the burning time"
        else:
            expr_str = str(self.expr).format(e=e, debug=debug) if e is not None and debug else str(self.expr)
            return f"the {cook_time and 'cooking' or 'burning'} time of {expr_str}"

    def get_return_type(self):
        return Timespan

    @staticmethod
    def accept_change(mode):
        if mode in [Changer.ADD, Changer.REMOVE, Changer.SET]:
            return [Timespan]
        else:
            return None

    def change(self, e=None, delta=None, mode=0):
        if not isinstance(delta, list) or len(delta) == 0:
            return
        value = None
        ci = DefaultClasses.TIMESPAN
        arithmetic = ci.get_relative_math()
        changed_time = Timespan(delta[0])
        for original in self.expr.get_array(e):
            if any_furnace.is_type(original):
                furnace_state = (Furnace)(original.get_state())
                time = value.apply(Timespan.from_ticks(cook_time and furnace_state.cook_time or furnace_state.burn_time))
                if mode == Changer.ADD:
                    furnace_state.set_cook_time((short)time)
                elif mode == Changer.REMOVE:
                    furnace_state.set_burn_time((short)(furnace_state.get_burn_time() - time))
                else:
                    furnace_state.set_cook_time((short)time)

    @staticmethod
    def register_expression():
        Skript.register_expression(ExprBurnCookTime, Timespan, ExpressionType.PROPERTY,
                                  "[the] burn[ing] time",
                                  "[the] (burn|1¦cook)[ing] time of %blocks%",
                                  "%blocks%'s (burn|1¦cook)[ing] time")
```

Note that Python does not support static initialization blocks like Java. Therefore, the `register_expression` method is moved to a separate function and can be called manually when needed.

Also note that some parts of the code are simplified or removed as they do not have direct equivalent in Python.