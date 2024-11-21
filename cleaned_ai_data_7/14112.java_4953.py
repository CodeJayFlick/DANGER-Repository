class LordBaelish:
    def __init__(self):
        pass

    def __init__(self, obs):
        super().__init__(obs)

    def time_passes(self, day: str) -> None:
        if day == 'Friday':
            self.notify_observers('STARK_SIGHTED')
