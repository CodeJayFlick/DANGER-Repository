import math

class ExprFoodLevel:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {
            "pattern": r"[the] (food|hunger)[[ ](level|met(er|re)|bar)] [of %player%]",
            "aliases": ["food", "hunger level", "meter", "bar"],
            "description": "The food level of a player from 0 to 10.",
        }

    def init(self, vars):
        self.expr = vars[0]
        return True

    def get(self, event=None):
        if isinstance(event, dict) and 'food_level' in event:
            return [event['food_level']]
        else:
            return [self.expr.get_food_level()]

    @property
    def return_type(self):
        return float

    def __str__(self, event=None):
        return f"the food level of {self.expr}"

    def accept_change(self, mode):
        if mode == 'remove_all':
            return None
        else:
            return [float]

    def change(self, event, delta, mode):
        assert mode != 'remove_all'

        s = 0.5 * float(delta[0]) if delta is not None else 0

        for player in self.expr.get_players(event):
            food = 20
            if isinstance(event, dict) and 'food_level' in event:
                food = event['food_level']
            elif mode == 'set':
                food = s
            elif mode == 'delete':
                food = max(0, food - s)
            elif mode == 'add':
                food = min(20, food + s)

        if isinstance(event, dict):
            event['food_level'] = food
        else:
            player.set_food_level(food)

    def set_time(self, time):
        return super().set_time(time, FoodLevelChangeEvent, self.expr)
