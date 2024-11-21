class SkriptEventHandler:
    def __init__(self):
        self.listeners = [PriorityListener(EventPriority.LOWEST), PriorityListener(EventPriority.HIGHEST)]
        self.triggers = []
        self.self_registered_triggers = []

    class PriorityListener:
        def __init__(self, priority):
            self.priority = priority
            self.registered_events = set()
            self.last_event = None

        def executor(self, listener, event):
            if self.last_event == event:  # an event is received multiple times if multiple superclasses of it are registered
                return
            self.last_event = event
            check(event, self.priority)

    class Trigger:
        def __init__(self, events, execute_function):
            self.events = set(events)
            self.execute_function = execute_function

    def add_trigger(self, events, trigger):
        for e in events:
            self.triggers.append((e, trigger))

    def log_event_start(self, event):
        if not Skript.log_very_high():
            return
        print("")
        print("== " + str(event.__class__.__name__) + " ==")

    def log_event_end(self):
        if not Skript.log_very_high():
            return
        print("== took {} milliseconds".format((time.time() - start_time) / 1000000))

    def add_self_registering_trigger(self, trigger):
        self.self_registered_triggers.append(trigger)

    @staticmethod
    def remove_triggers(script):
        info = ScriptInfo()
        info.files += 1

        previous_size = len(SkriptEventHandler.triggers)
        SkriptEventHandler.triggers[:] = [pair for pair in SkriptEventHandler.triggers if script != pair[1].script]
        info.triggers += previous_size - len(SkriptEventHandler.triggers)

        for i, t in enumerate(self.self_registered_triggers):
            if script == t.script:
                info.triggers += 1
                (t.event).unregister(t)
                self.self_registered_triggers.remove(i)
                i -= 1

        return info

    @staticmethod
    def remove_all_triggers():
        SkriptEventHandler.triggers.clear()
        for t in self.self_registered_triggers:
            (t.event).unregister_all()
        self.self_registered_triggers.clear()

    @staticmethod
    def register_bukkit_events():
        for pair in SkriptEventHandler.triggers:
            e = pair[0]
            priority = pair[1].event.priority

            listener = next((l for l in SkriptEventHandler.listeners if l.priority == priority), None)
            executor = listener.executor

            registered_events = set()
            if not any(e.__class__ in r for r in [pair[1].events]):
                registered_events.add(e.__class__)
                Bukkit.get_plugin_manager().register_event(e, listener, priority, executor)

    @staticmethod
    def contains_superclass(classes, c):
        return classes and (c in classes or any(cl.is_assignable_from(c) for cl in classes))

    listen_cancelled = set()
