class OrcKingdomFactory:
    def create_castle(self):
        return OrcCastle()

    def create_king(self):
        return OrcKing()

    def create_army(self):
        return OrcArmy()


# Note: The following classes are not provided in the original Java code, so I assume they exist elsewhere.
class Castle:
    pass

class King:
    pass

class Army:
    pass

class OrcCastle(Castle):
    pass

class OrcKing(King):
    pass

class OrcArmy(Army):
    pass
