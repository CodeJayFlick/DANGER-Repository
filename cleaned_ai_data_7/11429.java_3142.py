class AssemblyNumericTerminal:
    PREFIX_HEX = "0x"
    PREFIX_OCT = "0"

    def __init__(self, name: str, bitsize: int):
        self.name = name
        self.bitsize = bitsize

    def __str__(self) -> str:
        if self.bitsize == 0:
            return f"[num:{self.name}]"
        else:
            return f"[num{self.bitsize}:{self.name}]"

    def match(self, buffer: str):
        col = self.match(buffer, 0, None)
        if not col:
            return None
        elif len(col) == 1:
            return list(col)[0]
        else:
            raise AssertionError("Multiple results for a numeric terminal?: " + str(col))

    def match(self, buffer: str, pos: int):
        if pos >= len(buffer):
            return set()
        if buffer[pos] == '+':
            return self.matchLiteral(pos + 1, buffer)
        elif buffer[pos] == '-':
            return self.matchLiteral(pos + 1, buffer, True)
        else:
            return self.match(pos, buffer)

    def match(self, s: int, buffer: str):
        if s >= len(buffer):
            return set()
        # Try a literal number first
        if buffer[s].isdigit():
            return self.matchLiteral(s, buffer)
        # Now, try a label
        b = s
        while b < len(buffer):
            c = buffer[b]
            if c.isalnum() or c == '_':
                b += 1
                continue
            break
        lab = buffer[s:b]
        val = self.labels.get(lab)
        if val is None:
            return set()
        return {AssemblyParseNumericToken(self.grammar, self, lab, val)}

    def matchLiteral(self, s: int, buffer: str):
        if buffer.regionmatch(s, self.PREFIX_HEX, 0, len(self.PREFIX_HEX)):
            return self.matchHex(s + len(self.PREFIX_HEX), buffer)
        elif buffer.regionmatch(s, self.PREFIX_OCT, 0, len(self.PREFIX_OCT)):
            return self.matchOct(s + len(self.PREFIX_OCT), buffer)
        else:
            return self.matchDec(s, buffer)

    def makeToken(self, str: str, num: str, radix: int):
        if not num:
            return set()
        try:
            val = int(num, radix)
            # TODO: I'd really like to know whether or not the printpiece can take a signed value.
            if self.bitsize != 0 and self.bitsize != 64:
                if val < (1 << (self.bitsize - 1)):
                    return set()
                elif val >= 1 << self.bitsize:
                    return set()
            return {AssemblyParseNumericToken(self.grammar, self, str, val)}
        except ValueError:
            return set()

    def matchHex(self, s: int):
        b = s
        while b < len(buffer):
            c = buffer[b]
            if '0' <= c <= '9' or 'A' <= c <= 'F':
                b += 1
                continue
            break
        return self.makeToken(buffer[s:b], buffer[s + len(self.PREFIX_HEX):b], 16)

    def matchDec(self, s: int):
        b = s
        while b < len(buffer):
            c = buffer[b]
            if '0' <= c <= '9':
                b += 1
                continue
            break
        return self.makeToken(buffer[s:b], buffer[s + len(self.PREFIX_HEX):b], 10)

    def matchOct(self, s: int):
        b = s
        while b < len(buffer):
            c = buffer[b]
            if '0' <= c <= '7':
                b += 1
                continue
            break
        return self.makeToken(buffer[s:b], "0", 8)

    def getSuggestions(self, got: str) -> set:
        s = set(suggestions)
        labelcount = 0
        for lab in labels.keys():
            if labelcount >= MAX_LABEL_SUGGESTIONS:
                break
            if lab.startswith(got):
                s.add(lab)
                labelcount += 1
        return s

    def getBitSize(self) -> int:
        return self.bitsize


class AssemblyParseNumericToken:
    def __init__(self, grammar: 'AssemblyGrammar', terminal: 'AssemblyNumericTerminal', str: str, val):
        self.grammar = grammar
        self.terminal = terminal
        self.str = str
        self.val = val

    def __str__(self) -> str:
        return f"{self.terminal.name}:{self.val}"
