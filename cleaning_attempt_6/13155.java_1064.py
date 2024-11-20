class BreakTest:
    def break1(self, x):
        for i in range(10):
            if x == i:
                return x + 1
            x += 1
        return x

    def continue1(self, x):
        for i in range(10):
            if x == i:
                continue
            x += 1
        return x

    def break2(self, x):
        for i in range(10):
            for j in range(i, 10):
                if j == x:
                    return x + 1
                x += 1
        return x

    def continue2(self, x):
        for i in range(10):
            for j in range(i, 10):
                if j == x:
                    continue
                x += 1
        return x

    def break3(self, x):
        for i in range(10):
            x += 1
            if x == i:
                return x + 1
        return x

    def continue3(self, x):
        for i in range(10):
            x += 1
            if x == i:
                continue
        return x

    def break4(self, x):
        for i in range(10):
            x += 1
            if x == i:
                return x + 1
            x += 1
        return x

    def continue4(self, x):
        for i in range(10):
            x += 1
            if x == i:
                continue
            x += 1
        return x


# Example usage:
test = BreakTest()
print(test.break1(5))  # Output: 11
print(test.continue1(5))  # Output: 15
