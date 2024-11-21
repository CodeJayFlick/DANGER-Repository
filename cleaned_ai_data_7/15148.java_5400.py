class Statue:
    def __init__(self, id):
        self.id = id
        self.frames = 0
        self.delay = 0

    def update(self):
        if self.frames + 1 == self.delay:
            self.shoot_lightning()
            self.frames = 0
        else:
            self.frames += 1

    def shoot_lightning(self):
        print(f"Statue {self.id} shoots lightning!")
