class GiantModel:
    def __init__(self, health: str, fatigue: str, nourishment: str):
        self.health = health
        self.fatigue = fatigue
        self.nourishment = nourishment


class GiantView:
    pass  # This class is empty in the Java code. We can keep it as-is.


class GiantController:
    def __init__(self, giant_model: 'GiantModel', view: 'GiantView'):
        self.giant_model = giant_model
        self.view = view

    def update_view(self):
        # This method is empty in the Java code. We can keep it as-is.
        pass

    def set_health(self, health: str):
        self.giant_model.health = health

    def set_nourishment(self, nourishment: str):
        self.giant_model.nourishment = nourishment

    def set_fatigue(self, fatigue: str):
        self.giant_model.fatigue = fatigue


def main():
    giant_model = GiantModel('HEALTHY', 'ALERT', 'SATURATED')
    view = GiantView()
    controller = GiantController(giant_model, view)

    # initial display
    controller.update_view()

    # controller receives some interactions that affect the giant
    controller.set_health('WOUNDED')
    controller.set_nourishment('HUNGRY')
    controller.set_fatigue('TIRED')

    # redisplay
    controller.update_view()


if __name__ == "__main__":
    main()
