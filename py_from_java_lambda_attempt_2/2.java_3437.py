Here is the translation of the Java interface `BukkitBrigadierCommandSource` to a Python class:
```python
class BukkitBrigadierCommandSource:
    def get_bukkit_entity(self) -> None | 'Entity':
        ...

    def get_bukkit_world(self) -> None | 'World':
        ...

    def get_bukkit_location(self) -> None | 'Location':
        ...

    def get_bukkit_sender(self) -> 'CommandSender':
        ...
```
Note that I used the `->` syntax to indicate the return type of each method, and also used the `None | 'Type'` syntax to represent a nullable return value (similar to Java's `@Nullable` annotation).