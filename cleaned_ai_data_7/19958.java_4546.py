class Timespan:
    m_tick = Noun("time.tick")
    m_second = Noun("time.second")
    m_minute = Noun("time.minute")
    m_hour = Noun("time.hour")
    m_day = Noun("time.day")

    names = [m_tick, m_second, m_minute, m_hour, m_day]
    times = [50, 1000, 1000 * 60, 1000 * 60 * 60, 1000 * 60 * 60 * 24]

    parse_values = {}

    def __init__(self):
        self.millis = 0

    @classmethod
    def from_ticks(cls, ticks: int) -> 'Timespan':
        return cls(ticks * 50)

    @classmethod
    def from_ticks_i(cls, ticks: long) -> 'Timespan':
        return cls(int(ticks))

    @property
    def milli_seconds(self):
        return self.millis

    @property
    def ticks_i(self):
        return int(self.millis / 50.0)

    @classmethod
    def parse(cls, s: str) -> 'Timespan' or None:
        if not s:
            return None
        t = 0
        is_minecraft_time_set = False

        for subs in s.lower().split():
            sub = subs.strip()

            if sub == "and":
                continue

            amount = 1.0
            if Noun.is_indefinite_article(sub):
                amount = 1.0
                sub = next((i for i, x in enumerate(s.split()) if x == sub), None)
                s = ' '.join(x for i, x in enumerate(s.split()) if i != subs.index(sub))
            elif sub.isdigit():
                try:
                    amount = float(sub)
                except ValueError:
                    return None
                sub = next((i for i, x in enumerate(s.split()) if x == sub), None)
                s = ' '.join(x for i, x in enumerate(s.split()) if i != subs.index(sub))

            if "real" in Language.get_list("time"):
                if is_minecraft_time_set and not minecraft_time:
                    return None
                sub = next((i for i, x in enumerate(s.split()) if x == sub), None)
            elif "minecraft" in Language.get_list("time"):
                if is_minecraft_time_set and minecraft_time:
                    return None
                minecraft_time = True
                sub = next((i for i, x in enumerate(s.split()) if x == sub), None)

            d = parse_values.get(sub.lower())
            if not d:
                return None

            t += math.floor(amount * d)
            is_minecraft_time_set = True

        return cls(t)

    @classmethod
    def from_string(cls, s: str) -> 'Timespan' or None:
        for i in range(len(simple_values)):
            if int(math.ceil(millis / simple_values[i].get_second())) >= 1.0:
                amount = (millis % simple_values[i].get_second()) / simple_values[i + 1].get_second()
                return f"{int(math.floor(amount))} {simple_values[i].first.with_amount(amount, flags)} and {math.ceil((amount - int(math.floor(amount))) * 100.0)}"
        return s

    def __str__(self):
        return str(self)

    @classmethod
    def from_string(cls, millis: long) -> 'Timespan' or None:
        for i in range(len(simple_values)):
            if millis >= simple_values[i].get_second():
                amount = (millis % simple_values[i].get_second()) / simple_values[i + 1].get_second()
                return f"{int(math.floor(amount))} {simple_values[i].first.with_amount(amount, flags)}"
        return str(millis)

    def __repr__(self):
        return self.__str__()

    @classmethod
    def from_string(cls, millis: long) -> 'Timespan' or None:
        for i in range(len(simple_values)):
            if millis >= simple_values[i].get_second():
                amount = (millis % simple_values[i].get_second()) / simple_values[i + 1].get_second()
                return f"{int(math.floor(amount))} {simple_values[i].first.with_amount(amount, flags)}"
        return str(millis)

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, Timespan):
            return False
        return self.millis == other.millis

    def __lt__(self, other):
        d = other.millis - self.millis
        if d > 0.0:
            return True
        elif d < 0.0:
            return False
        else:
            return False

    def __hash__(self) -> int:
        prime = 31
        result = 1
        result *= (prime * result + self.millis // 10**9)
        return result
