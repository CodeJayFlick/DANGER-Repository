Here is the translation of the given Java code into equivalent Python:

```Python
class SkriptEventInfo:
    def __init__(self, name: str, patterns: list[str], c: type[E], origin_class_path: str, events: tuple[type[Event], ...]) -> None:
        self.name = name
        self.events = events

        if not name.startswith("*"):
            self.name = "On " + name

        self.id = "".join(name.lower().replace("[#'\"<>/&]", "_").split())

    def description(self, *description: str) -> 'SkriptEventInfo':
        self.description = list(description)
        return self

    def examples(self, *examples: str) -> 'SkriptEventInfo':
        self.examples = list(examples)
        return self

    def since(self, since: str) -> 'SkriptEventInfo':
        self.since = since
        return self

    def documentation_id(self, id: str) -> 'SkriptEventInfo':
        self.documentation_id = id
        return self

    def required_plugins(self, *plugin_names: str) -> 'SkriptEventInfo':
        self.required_plugins = list(plugin_names)
        return self

    @property
    def get_id(self) -> str:
        return self.id

    @property
    def get_name(self) -> str:
        return self.name

    @property
    def get_description(self) -> tuple[str, ...]:
        return self.description or ()

    @property
    def get_examples(self) -> tuple[str, ...]:
        return self.examples or ()

    @property
    def get_since(self) -> str | None:
        return self.since

    @property
    def get_required_plugins(self) -> tuple[str, ...] | None:
        return self.required_plugins
```

Note that the `@Nullable` and `@NonNull` annotations are not directly translatable to Python. In this translation, I have assumed that these annotations were meant to indicate whether a variable can be set to `None`, rather than indicating any specific Java semantics.