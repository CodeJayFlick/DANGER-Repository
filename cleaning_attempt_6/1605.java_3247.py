class LldbProcessReplacedEvent:
    def __init__(self, info):
        super().__init__(info)

    def new_state(self) -> int:
        # NB: it's very tempting to relay the info we have, but
        #   doing so fouls up a lot of the tests because the stopped
        #   message arrives ahead of breakpointHit

        return None  # equivalent to Java's null return value
