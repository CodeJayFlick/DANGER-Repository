import logging

class LambdaStrategy:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    class Strategy:
        MELEE_STRATEGY = "With your Excalibur you severe the dragon's head!"
        PROJECTILE_STRATEGY = "You shoot the dragon with the magical crossbow and it falls dead on the ground!"
        SPELL_STRATEGY = "You cast the spell of disintegration and the dragon vaporizes in a pile of dust!"

        def __init__(self, strategy_name):
            self.strategy_name = strategy_name

        def execute(self):
            if self.strategy_name == LambdaStrategy.Strategy.MELEE_STRATEGY:
                print("With your Excalibur you severe the dragon's head!")
            elif self.strategy_name == LambdaStrategy.Strategy.PROJECTILE_STRATEGY:
                print("You shoot the dragon with the magical crossbow and it falls dead on the ground!")
            elif self.strategy_name == LambdaStrategy.Strategy.SPELL_STRATEGY:
                print("You cast the spell of disintegration and the dragon vaporizes in a pile of dust!")

if __name__ == "__main__":
    strategy = LambdaStrategy().Strategy(LambdaStrategy.Strategy.MELEE_STRATEGY)
    strategy.execute()
