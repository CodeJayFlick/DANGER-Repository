import collections
from typing import Set, Collection, Any

class PlayerUtils:
    def __init__(self):
        pass

    invi_update: Set[Any] = set()

    @staticmethod
    def update_inventory(p: Any) -> None:
        if p is not None:
            PlayerUtils.invi_update.add(p)

    task: Any = Task(Skript.getInstance(), 1, 1)
    task.run = lambda: (
        try:
            for player in PlayerUtils.invi_update.copy():
                player.update_inventory()
        except NullPointerException as e:
            if Skript.debug():
                print(e.stacktrace())
        finally:
            PlayerUtils.invi_update.clear())

    has_collection_get_online_players: bool
    get_online_players_method: Any = None

    @staticmethod
    def get_online_players() -> Collection[Any]:
        if has_collection_get_online_players:
            return list(Bukkit.get_online_players())
        else:
            try:
                method = Bukkit.__class__.getattribute("get_online_players")
            except AttributeError as e:
                Skript.outdated_error(e)
            except SecurityError as e:
                Skript.exception(e)

            if get_online_players_method is None:
                try:
                    get_online_players_method = getattr(Bukkit, "get_online_players")
                except (AttributeError, SecurityError) as e:
                    Skript.outdated_error(e)

            try:
                players = list(get_online_players_method())
                return players
            except Exception as e:
                Skript.exception(e)
        return collections.deque()

    @staticmethod
    def can_eat(p: Any, food: Any) -> bool:
        gm = p.game_mode
        if gm in [GameMode.CREATIVE, GameMode.SPECTATOR]:
            return False

        edible = food.is_edible()
        if not edible:
            return False

        special = None
        for f in [Material.GOLDEN_APPLE, Material.CHORUS_FRUIT]:
            if f == food:
                special = True
                break

        if p.food_level < 20 or special:
            return True
        return False


class Task:
    def __init__(self, instance: Any, a: int, b: int):
        self.instance = instance
        self.a = a
        self.b = b

    run = lambda: None
