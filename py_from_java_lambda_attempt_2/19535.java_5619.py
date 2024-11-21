Here is the translation of the Java code into Python:

```Python
class ExprDirection:
    def __init__(self):
        self.amount = None
        self.direction = None
        self.next = None
        self.relative_to = None
        self.horizontal = False
        self.facing = False
        self.yaw = 0

    @staticmethod
    def register_expression():
        Skript.register_expression("Direction", Direction, ExpressionType.COMBINED,
                                  "([%-number% [(block|met(er|re))[s]]] in [the] (0¦direction|1¦horizontal direction|2¦facing|3¦horizontal facing) of %entity/block%'[s]  (of|from|)",
                                  "([%-number% [(block|met(er|re))[s]]] in %entity/block%'[s]  (0¦in [ ]front [of]|0¦forward[s]|2¦behind|2¦backwards|[to the]  (1¦right|-1¦left) [of])",
                                  "([%-number% [(block|met(er|re))[s]]] horizontal[ly]  (0¦in [ ]front [of]|0¦forward[s]|2¦behind|2¦backwards|[to the]  (1¦right|-1¦left) [of])")

    def init(self, exprs: list, matched_pattern: int, is_delayed: bool, parse_result):
        self.amount = exprs[0]
        if matched_pattern == 0:
            self.direction = Vector(by_mark[parse_result.mark].get_mod_x(), by_mark[parse_result.mark].get_mod_y(), by_mark[parse_result.mark].get_mod_z())
            if exprs[1] is not None and isinstance(exprs[1], ExprDirection) and (exprs[1]).direction is not None:
                self.next = exprs[1]
        elif matched_pattern in [1, 2]:
            self.relative_to = exprs[1]
            self.horizontal = parse_result.mark % 2 != 0
            self.facing = parse_result.mark >= 2
        elif matched_pattern in [3, 4]:
            self.yaw = math.pi / 2 * parse_result.mark
            self.horizontal = matched_pattern == 4

    def get(self, e):
        if self.amount is not None:
            n = self.amount.get_single(e)
            if n is None:
                return []
            ln = n.double_value()
            if self.direction is not None:
                v = self.direction.clone().multiply(ln)
                d = self.next
                while d is not None:
                    n2 = d.amount.get_single(e) if d.amount is not None else 1
                    if n2 is None:
                        return []
                    assert d.direction is not None
                    v.add(d.direction.clone().multiply(n2.double_value()))
                    d = d.next
                assert v is not None
                return [Direction(v)]
            elif self.relative_to is not None:
                o = self.relative_to.get_single(e)
                if o is None:
                    return []
                if isinstance(o, Block):
                    f = Direction.get_facing(o)
                    if f == BlockFace.SELF or (self.horizontal and (f == BlockFace.UP or f == BlockFace.DOWN)):
                        return [Direction.ZERO]
                    return [Direction(f, ln)]
                else:
                    l = o.location
                    if not self.horizontal:
                        v = Vector(l.direction.normalize().multiply(ln))
                        assert v is not None
                        return [Direction(v)]
                    pitch = Direction.pitch_to_radians(l.pitch)
                    assert -math.pi / 2 <= pitch and pitch <= math.pi / 2
                    if pitch > math.pi / 4:
                        return [Direction([0, ln, 0])]
                    if pitch < -math.pi / 4:
                        return [Direction([0, -ln, 0])]
            else:
                return [Direction(self.horizontal, self.yaw, ln)]

    def is_single(self):
        return True

    def get_return_type(self):
        return Direction

    def __str__(self, e=None, debug=False):
        if self.amount is not None:
            amount_str = str(self.amount) + " meter(s)"
        else:
            amount_str = ""
        if self.direction is not None:
            direction_str = Direction.__str__(self.direction)
        elif self.relative_to is not None:
            relative_to_str = f" in {'horizontal ' if self.horizontal else ''}{'facing' if self.facing else 'direction'} of {self.relative_to}"
        else:
            direction_str = "horizontally"
        return amount_str + ("" if direction_str == "" else " ") + direction_str
```

Please note that Python does not have direct equivalent to Java's `@Override` annotation.