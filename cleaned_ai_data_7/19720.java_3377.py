class VectorNormalize:
    def __init__(self):
        self.vector = None

    @staticmethod
    def register_expression():
        pass  # Skript.registerExpression(ExprVectorNormalize.class, Vector.class, ExpressionType.SIMPLE, "normalize[d] %vector%", "%vector% normalized")

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result: dict) -> bool:
        self.vector = exprs[0]
        return True

    def get(self, event):
        v = self.vector.get(event)
        if v is None:
            return []
        return [v.clone().normalize()]

    @property
    def single(self) -> bool:
        return True

    @property
    def return_type(self) -> type:
        from org.bukkit.util import Vector  # Import the Vector class (assuming it's available)
        return Vector

    def __str__(self, event: dict, debug: bool):
        return f"normalized {self.vector.__str__(event, debug)}"
