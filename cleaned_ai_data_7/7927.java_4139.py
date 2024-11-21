class MDVtordispex:
    def __init__(self):
        pass  # equivalent to super( dmang )

    def parse_internal(self) -> None:
        a = MDEncodedNumber()
        b = MDEncodedNumber()
        c = MDEncodedNumber()
        d = MDEncodedNumber()

        a.parse()  # TODO: what is this? Possibly the displacement?
        b.parse()  # TODO: what is this? Possibly the adjustment?
        c.parse()  # TODO: what is this?
        d.parse()  # TODO: what is this?

        self.name_modifier = f"vtordispex{{{a},{b},{c},{d}}}"


class MDEncodedNumber:
    def parse(self) -> None:
        pass
