Here is the translation of the given Java code into Python:

```Python
class OpenBook:
    def __init__(self):
        self.book = None
        self.players = None

    @staticmethod
    def register_effect():
        if hasattr(Player, 'open_book') and callable(getattr(Player, 'open_book')):
            from skript import Skript
            Skript.register_event_handler(OpenBook, "(open|show) book %itemtype% (to|for) %players%",)

    @property
    def book(self):
        return self._book

    @book.setter
    def book(self, value):
        self._book = value

    @property
    def players(self):
        return self._players

    @players.setter
    def players(self, value):
        self._players = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) > 1:
            self.book = exprs[0]
            self.players = exprs[1]

    def execute(self, e):
        item_type = self.book.get_single(e)
        if item_type is not None:
            for player in self.players.get_array(e):
                player.open_book(item_type)

    def __str__(self, e=None, debug=False):
        return f"open book {self.book} to {self.players}"
```

Please note that this Python code does not exactly translate the given Java code. It is a simplified version of it and may not work as expected in all scenarios.