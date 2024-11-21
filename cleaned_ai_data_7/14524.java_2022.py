# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class PartyMember:
    """Interface for party members interacting with `Party`."""

    def joined_party(self, party):
        pass

    def party_action(self, action):
        pass

    def act(self, action):
        pass
