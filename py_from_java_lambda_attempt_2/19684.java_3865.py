Here is a translation of the Java code into equivalent Python:

```Python
import.bukkit as bukkit
from typing import List, Tuple

class ExprSpawn:
    def __init__(self):
        self.skript = None  # Skript instance (not sure what this does)

    @property
    def name(self) -> str:
        return "Spawn"

    @property
    def description(self) -> str:
        return "The spawn point of a world."

    @property
    def examples(self) -> List[Tuple[str]]:
        return [("teleport all players to spawn",),
                ("set the spawn point of 'world' to the player's location",)]

    @property
    def since(self) -> str:
        return "1.4.2"

    def init(self, exprs: List[Expression], matched_pattern: int, is_delayed: bool, parse_result: ParseResult):
        self.expr = exprs[0]
        return True

    def get(self, e: Event, source: bukkit.World) -> Tuple[bukkit.Location]:
        if self.get_time() == -1 and isinstance(e, SpawnChangeEvent) and not Delay.is_delayed(e):
            return [(SpawnChangeEvent)e].get_previous_location(),
        return tuple(source.get_spawn_location() for _ in range(len(source)))

    def get_return_type(self) -> type:
        return bukkit.Location

    def __str__(self, e: Event = None, debug: bool = False) -> str:
        if e is not None and isinstance(e, SpawnChangeEvent):
            return f"spawn of {self.expr.__str__(e, debug)}"
        else:
            return "spawn"

    def accept_change(self, mode: ChangeMode) -> List[type]:
        if mode == ChangeMode.SET:
            return [bukkit.Location]
        return []

    def change(self, e: Event, delta: Tuple[object], mode: ChangeMode):
        assert mode == ChangeMode.SET
        assert delta is not None

        location = Location(*delta)
        for world in self.expr.get_array(e):
            world.set_spawn_location(location.block_x, location.block_y, location.block_z)

    def set_time(self, time: int) -> bool:
        return super().set_time(time, self.expr, SpawnChangeEvent)


class Expression:
    pass


class ParseResult:
    pass


class Delay:
    @staticmethod
    def is_delayed(e: Event):
        # not sure what this does
        pass

    @staticmethod
    def get_previous_location(self) -> bukkit.Location:
        # not sure what this does
        pass


class ChangeMode:
    SET = 0
```

Please note that Python doesn't have direct equivalent of Java's `@Name`, `@Description`, etc. annotations, so I've used properties to represent these values in the class.