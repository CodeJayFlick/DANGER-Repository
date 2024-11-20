Here is a translation of the Java code into equivalent Python:

```Python
class AffectedEntities:
    def __init__(self):
        self.name = "Affected Entities"
        self.description = ("The affected entities in an area cloud effect event.")
        self.examples = [
            {"on": "area cloud effect:"},
            {"loop": ["affected entities:", 
                      "\tif loop-value is a player:",
                      "\t\tsend \"WARNING: you've step on an area effect cloud!\" to loop-value"]}
        ]
        self.since = "2.4"

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if not isinstance(parser.current_event(), AreaEffectCloudApplyEvent):
            print("The 'affected entities' expression may only be used in an area cloud effect event.")
            return False
        return True

    def get(self, e):
        if isinstance(e, AreaEffectCloudApplyEvent):
            return list((e.get_affected_entities()))
        return None

    def iterator(self, e):
        if isinstance(e, AreaEffectCloudApplyEvent):
            return (e.get_affected_entities()).__iter__()
        return super().iterator(e)

    def is_single(self):
        return False

    def is_default(self):
        return True

    def get_return_type(self):
        return LivingEntity.__class__

    def __str__(self, e=None, debug=False):
        if not isinstance(e, AreaEffectCloudApplyEvent) and not debug:
            return "the affected entities"
```

Note that this translation does not include the Java-specific parts like annotations or static blocks. Also, Python is a dynamically-typed language so you don't need to specify types for variables explicitly.