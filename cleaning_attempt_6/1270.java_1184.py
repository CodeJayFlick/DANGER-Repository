class GdbBreakpointLocation:
    WATCHPOINT_LOCATION_PREFIX = "-location "

    def __init__(self, number: int, sub: int, enabled: bool, addr: str, inferior_ids: list):
        self.number = number
        self.sub = sub
        self.enabled = enabled
        self.addr = addr
        self.inferior_ids = tuple(inferior_ids)

    def __str__(self) -> str:
        return f"<Loc number={self.number}.{self.sub},enabled={self.enabled},addr={self.addr},iids={self.inferior_ids}>"

    @property
    def get_number(self):
        return self.number

    @property
    def get_sub(self):
        return self.sub if self.sub else 0

    @property
    def is_enabled(self) -> bool:
        return self.enabled

    @property
    def get_addr(self) -> str:
        return self.addr

    def addr_as_long(self) -> int:
        try:
            return int(GdbParsingUtils.parse_prefixed_hex(self.addr), 16)
        except ValueError as e:
            raise Exception(f"Failed to parse address {self.addr}: {str(e)}")

    @property
    def get_inferior_ids(self):
        return self.inferior_ids

    def __hash__(self) -> int:
        return hash((self.number, self.sub, self.enabled, self.addr, tuple(self.inferior_ids)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GdbBreakpointLocation):
            return False
        that = other
        if self.number != that.number:
            return False
        if self.sub != that.sub:
            return False
        if self.enabled != that.enabled:
            return False
        if self.addr != that.addr:
            return False
        if self.inferior_ids != that.inferior_ids:
            return False
        return True

