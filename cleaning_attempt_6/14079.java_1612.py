class SpaceStationIss(SpaceStationMir):
    def __init__(self, left, top, right, bottom):
        super().__init__(left, top, right, bottom)

    def collision(self, gameObject):
        gameObject.collision_resolve(self)
