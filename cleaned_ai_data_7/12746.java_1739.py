class CodeUnitLCS:
    def __init__(self, x_list: list, y_list: list):
        self.x_list = x_list
        self.y_list = y_list

    @property
    def length_of_x(self) -> int:
        return len(self.x_list)

    @property
    def length_of_y(self) -> int:
        return len(self.y_list)

    def matches(self, x: dict, y: dict) -> bool:
        return x['arity'] == y['arity'] and x['mnemonic'] == y['mnemonic']

    def value_of_x(self, index: int) -> dict:
        return self.x_list[index - 1]

    def value_of_y(self, index: int) -> dict:
        return self.y_list[index - 1]
