Here is a translation of the Java code into Python:

```Python
import logging
from typing import List, Optional

class RegionBorder:
    def __init__(self):
        self.enter = None  # type: bool
        self.regions = None  # type: Optional['Literal[Region]']

    @staticmethod
    def register_event():
        if not hasattr(RegionBorder, 'registered'):
            from skript import Skript

            Skript.register_event("Region Enter/Leave", RegionBorder)
            EventValues.register_event_value(RegionBorderEvent, Region, lambda e: e.get_region())
            EventValues.register_event_value(RegionBorderEvent, Player, lambda e: e.get_player())

    def init(self, args: List[Literal], matched_pattern: int, parse_result: ParseResult) -> bool:
        self.enter = parse_result.mark == 0
        if len(args) > 0:
            self.regions = Literal(Region)(args[0])
        return True

    @staticmethod
    def call_event(r: Region, me: PlayerMoveEvent, enter: bool):
        p = me.get_player()
        e = RegionBorderEvent(r, p, enter)
        for t in triggers:
            if ((EvtRegionBorder(t)).applies(e)):
                t.execute(e)

    # even WorldGuard doesn'nt have events, and this way all region plugins are supported for sure.
    @staticmethod
    def register():
        from skript import Skript

        if not hasattr(RegionBorder, 'registered'):
            ee = EventExecutor()
            last_event = None  # type: Optional[Event]

            class Listener:
                pass

            def execute_listener(listener: Listener, event: Event):
                nonlocal last_event
                if event == last_event:
                    return
                last_event = event
                e = PlayerMoveEvent(event)
                to = e.get_to()
                from_ = e.get_from()
                old_rs = RegionsPlugin.get_regions_at(from_)
                new_rs = RegionsPlugin.get_regions_at(to)
                for r in old_rs:
                    if not new_rs.contains(r):
                        RegionBorder.call_event(r, e, False)
                for r in new_rs:
                    if not old_rs.contains(r):
                        RegionBorder.call_event(r, e, True)

            ee.execute_listener = execute_listener
            Skript.get_instance().get_plugin_manager().register_event(PlayerMoveEvent, Listener(), 0, ee, None, True)
            Skript.get_instance().get_plugin_manager().register_event(PlayerTeleportEvent, Listener(), 0, ee, None, True)
            Skript.get_instance().get_plugin_manager().register_event(PlayerPortalEvent, Listener(), 0, ee, None, True)

    def __str__(self, e: Optional[Event], debug: bool) -> str:
        r = self.regions
        return f"{'enter' if self.enter else 'leave'} of {'' if r is None else r.__str__(e, debug)}"

class Trigger:
    pass

triggers = []  # type: List[Trigger]

def register(self):
    triggers.append(self)
    self.register()

def unregister(self):
    triggers.remove(self)

def unregister_all():
    triggers.clear()
```

This Python code is a direct translation of the Java code. Note that this code does not include any specific region plugin, it only handles events related to regions and players moving in or out of those regions.