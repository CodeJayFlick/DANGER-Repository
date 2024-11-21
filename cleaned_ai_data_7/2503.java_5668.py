class TraceBreakpointKind:
    READ = 1 << 0
    WRITE = 1 << 1
    HW_EXECUTE = 1 << 2
    SW_EXECUTE = 1 << 3


class TraceBreakpointKindSet(set):
    @staticmethod
    def of(*kinds):
        return set(kinds)

    @staticmethod
    def copy_of(kinds):
        return set(kinds)


def decode(encoded, strict=False):
    result = set()
    names = {name.upper() for name in encoded.split(",")}
    for k in TraceBreakpointKind.__members__.values():
        if k.name in names:
            result.add(k)
            names.remove(k.name)
    if strict and any(names):
        raise ValueError(f"Unrecognized kinds: {', '.join(sorted(names))}")
    return set(result)


def encode(col):
    sb = []
    first = True
    for k, v in TraceBreakpointKind.__members__.items():
        if v in col:
            if not first:
                sb.append(",")
            else:
                first = False
            sb.append(v)
    return "".join(sb)


class TraceBreakpointKindSet(TraceBreakpointKindSet):
    def __init__(self, set):
        super().__init__(set)

    def __str__(self):
        return encode(self)


def main():
    print(decode("READ,WRITE"))


if __name__ == "__main__":
    main()
