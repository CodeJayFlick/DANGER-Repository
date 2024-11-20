class Delay:
    def __init__(self):
        self.duration = None

    @staticmethod
    def register_effect():
        Skript.register_effect(Delay)

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) > 0:
            self.duration = exprs[0]
        return True

    def walk(self, e):
        debug(e, True)
        start_time = time.time() if Skript.debug else None
        next_trigger_item = self.get_next()
        if next_trigger_item and Skript.is_enabled():
            delayed.add(e)
            d = self.duration.get_single_value(e)
            if d is not None:
                # Back up local variables
                local_vars = Variables.remove_locals(e)

                Bukkit.get_scheduler().schedule_sync_delayed_task(Skript.instance, lambda: run())

    def execute(self, e):
        raise UnsupportedOperationException()

    @staticmethod
    def add_delayed_event(event):
        delayed.add(event)

    @classmethod
    def is_delayed(cls, event):
        return delayed.contains(event)

    def __str__(self, e=None, debug=False):
        if e:
            return f"wait for {self.duration.__str__(e, debug)}..."
        else:
            return "wait for " + self.duration.__str__()

# Static variables
delayed = set()
