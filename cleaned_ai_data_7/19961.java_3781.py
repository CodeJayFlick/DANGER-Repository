class ParticleOption:
    def __init__(self, color: tuple, size: float):
        self.color = Color.from_bukkit_color(color)
        self.size = size

    @property
    def bukkit_color(self) -> tuple:
        return self.color

    @property
    def red(self) -> float:
        return self.color[0] / 255.0

    @property
    def green(self) -> float:
        return self.color[1] / 255.0

    @property
    def blue(self) -> float:
        return self.color[2] / 255.0

    def __str__(self):
        return f"ParticleOption{{color={self.color}, size={self.size}}}"
