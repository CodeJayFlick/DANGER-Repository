class GiantModel:
    def __init__(self, health: str, fatigue: str, nourishment: str):
        self._health = health
        self._fatigue = fatigue
        self._nourishment = nourishment

    @property
    def health(self) -> str:
        return self._health

    @health.setter
    def health(self, value: str):
        self._health = value

    @property
    def fatigue(self) -> str:
        return self._fatigue

    @fatigue.setter
    def fatigue(self, value: str):
        self._fatigue = value

    @property
    def nourishment(self) -> str:
        return self._nourishment

    @nourishment.setter
    def nourishment(self, value: str):
        self._nourishment = value

def test_set_health():
    model = GiantModel("HEALTHY", "ALERT", "SATURATED")
    assert model.health == "HEALTHY"
    for health in ["HEALTHY", "SICKLY"]:
        model.health = health
        assert model.health == health
        print(f"The giant looks {health}, alert and saturated.")

def test_set_fatigue():
    model = GiantModel("HEALTHY", "ALERT", "SATURATED")
    assert model.fatigue == "ALERT"
    for fatigue in ["ALERT", "TIRED"]:
        model.fatigue = fatigue
        assert model.fatigue == fatigue
        print(f"The giant looks healthy, {fatigue} and saturated.")

def test_set_nourishment():
    model = GiantModel("HEALTHY", "ALERT", "SATURATED")
    assert model.nourishment == "SATURATED"
    for nourishment in ["SATURATED", "HUNGRY"]:
        model.nourishment = nourishment
        assert model.nourishment == nourishment
        print(f"The giant looks healthy, alert and {nourishment}.")

if __name__ == "__main__":
    test_set_health()
    test_set_fatigue()
    test_set_nourishment()
