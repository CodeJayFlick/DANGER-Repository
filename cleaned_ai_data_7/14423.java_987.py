class CakeInfo:
    def __init__(self, id: Optional[int] = None, cake_topping_info=None, cake_layer_infos=None):
        self.id = id if id else None
        self.cake_topping_info = cake_topping_info
        self.cake_layer_infos = cake_layer_infos

    @property
    def total_calories(self) -> int:
        return sum(cake_layer_info.calories for cake_layer_info in self.cake_layer_infos) + (self.cake_topping_info.calories if self.cake_topping_info else 0)

    def __str__(self):
        return f"CakeInfo id={self.id} topping={self.cake_topping_info} layers={self.cake_layer_infos} totalCalories={self.total_calories}"
