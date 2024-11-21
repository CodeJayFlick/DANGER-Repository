class GdbFrameInfo:
    def __init__(self, level: str, addr: str, func: str, args: list):
        self.level = level
        self.addr = addr
        self.func = func
        self.args = args

    @staticmethod
    def parse_info(info_dict: dict) -> 'GdbFrameInfo':
        return GdbFrameInfo(
            info_dict.get('level'),
            info_dict.get('addr'),
            info_dict.get('func'),
            [arg for arg in info_dict['args']]
        )

    def __hash__(self):
        return hash((self.level, self.addr))

    def __str__(self):
        return f"<GdbFrameInfo level={self.level}, addr={self.addr}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GdbFrameInfo):
            return False
        that = other
        return self.level == that.level and self.addr == that.addr

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, value: str):
        self._level = value

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, value: str):
        self._addr = value

    @property
    def func(self):
        return self._func

    @func.setter
    def func(self, value: str):
        self._func = value

    @property
    def args(self):
        return self._args

    @args.setter
    def args(self, value: list):
        self._args = value
