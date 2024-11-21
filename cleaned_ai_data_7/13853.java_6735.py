# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class OrcKing:
    def __init__(self):
        self.build_chain()

    def build_chain(self):
        self.chain = OrcCommander(OrcOfficer(OrcSoldier(None)))

    def make_request(self, req: 'Request'):
        self.chain.handle_request(req)

# No equivalent to Java's package declaration in Python
