Here is the translation of the Java code into Python:

```Python
class EvtClick:
    TWO_HANDED = Skript.is_running_minecraft(1, 9)
    ALWAYS_PREFER_ITEM = not Skript.is_running_minecraft(1, 13)

    RIGHT_CLICK = 1
    LEFT_CLICK = 2
    ANY_CLICK = RIGHT_CLICK | LEFT_CLICK

    interact_tracker = ClickEventTracker(Skript.get_instance())
    entity_interact_tracker = ClickEventTracker(Skript.get_instance())

    def __init__(self):
        pass

    @staticmethod
    def register_event():
        event_types = [PlayerInteractEvent, PlayerInteractEntityEvent]
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing] (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  [(with|using|holding) %itemtype%]" % (RIGHT_CLICK, LEFT_CLICK),
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                              "[({}¦right|{}¦left)(| |-)][mouse(| |-)]click[ing]  (with|using|holding) %itemtype% on %-entitydata/itemtype%"",
                              "Called when a user clicks on a block, an entity or air with or without an item in their hand.",
                              "Please note that rightclick events with an empty hand while not looking at a block are not sent to the server, so there's no way to detect them.")
        Skript.register_event("Click", EvtClick, event_types,
                             