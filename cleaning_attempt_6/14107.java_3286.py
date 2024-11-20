class Event:
    STARK_SIGHTED = ("Stark sighted",)
    WARSHIPS_APPROACHING = ("Warships approaching",)
    TRAITOR_DETECTED = ("Traitor detected",)

    def __init__(self, description):
        self.description = description

    def __str__(self):
        return self.description
