# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class DragonSlayer:
    def __init__(self, strategy):
        self.strategy = strategy

    def change_strategy(self, strategy):
        self.strategy = strategy

    def go_to_battle(self):
        self.strategy.execute()
