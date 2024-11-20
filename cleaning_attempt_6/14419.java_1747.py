class App:
    def __init__(self):
        self.cake_baking_service = CakeBakingService()

    @staticmethod
    def main():
        initialize_data()
        cake_view = CakeViewImpl(App().cake_baking_service)
        cake_view.render()


def initialize_data(cake_baking_service: 'CakeBakingService') -> None:
    cake_baking_service.save_new_layer(CakeLayerInfo("chocolate", 1200))
    cake_baking_service.save_new_layer(CakeLayerInfo("banana", 900))
    cake_baking_service.save_new_layer(CakeLayerInfo("strawberry", 950))
    cake_baking_service.save_new_layer(CakeLayerInfo("lemon", 950))
    cake_baking_service.save_new_layer(CakeLayerInfo("vanilla", 950))

    cake_baking_service.save_new_topping(CakeToppingInfo("candies", 350))
    cake_baking_service.save_new_topping(CakeToppingInfo("cherry", 350))

    cake1 = CakeInfo(
        CakeToppingInfo("candies", 0),
        [CakeLayerInfo("chocolate", 0), 
         CakeLayerInfo("banana", 0), 
         CakeLayerInfo("strawberry", 0)]
    )
    try:
        App().cake_baking_service.bake_new_cake(cake1)
    except CakeBakingException as e:
        print(e)

    cake2 = CakeInfo(
        CakeToppingInfo("cherry", 0),
        [CakeLayerInfo("vanilla", 0), 
         CakeLayerInfo("lemon", 0), 
         CakeLayerInfo("strawberry", 0)]
    )
    try:
        App().cake_baking_service.bake_new_cake(cake2)
    except CakeBakingException as e:
        print(e)


class CakeViewImpl:
    def __init__(self, cake_baking_service: 'CakeBakingService'):
        self.cake_baking_service = cake_baking_service

    def render(self):
        pass


class CakeInfo:
    def __init__(self, topping_info: 'CakeToppingInfo', layers: list['CakeLayerInfo']):
        self.topping_info = topping_info
        self.layers = layers


class CakeBakingService:
    @staticmethod
    def save_new_layer(layer_info: 'CakeLayerInfo') -> None:
        pass

    @staticmethod
    def save_new_topping(topping_info: 'CakeToppingInfo') -> None:
        pass

    @staticmethod
    def bake_new_cake(cake_info: 'CakeInfo') -> None:
        raise CakeBakingException("Not implemented")


class CakeLayerInfo:
    def __init__(self, name: str, height: int):
        self.name = name
        self.height = height


class CakeToppingInfo:
    def __init__(self, name: str, weight: int):
        self.name = name
        self.weight = weight


class CakeBakingException(Exception):
    pass

if __name__ == "__main__":
    App().main()
