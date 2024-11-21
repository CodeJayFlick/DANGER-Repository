Here is a translation of the given Java code into equivalent Python:

```Python
from datetime import datetime

class LastLoginTime:
    def __init__(self):
        self.LAST_LOGIN = hasattr(OfflinePlayer, 'getLastLogin')

    @staticmethod
    def register():
        OfflinePlayers.register(LastLoginTime, (1|'last', 2|'first') + ' login', 'offlineplayers')

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.first = parse_result.mark == 2
        return super().init(exprs, matched_pattern, is_delayed, parse_result)

    @staticmethod
    def convert(player):
        if player:
            if self.LAST_LOGIN and hasattr(OfflinePlayer, 'getLastLogin'):
                return datetime.fromtimestamp(player.getLastLogin())
            elif not self.LAST_LOGIN:
                return datetime.fromtimestamp(player.getLastPlayed())

class OfflinePlayers:
    register = None

# This is a Python equivalent of Java's static class
LastLoginTime.register()
```

Please note that this translation assumes the existence of `OfflinePlayer` and other classes, which are likely defined elsewhere in your code.