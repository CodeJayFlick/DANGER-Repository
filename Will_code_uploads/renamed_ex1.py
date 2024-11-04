import numpy as np


def Method1(cities):
    Variable1 = []
    Variable2 = float('inf')
    for Variable3, Variable4 in enumerate(cities):
        Variable5 = [Variable3]
        Variable6 = 0
        Variable7, Variable8, Variable9 = get_closest(Variable4, cities,
            Variable5)
        Variable6 += Variable9
        Variable5.append(Variable7)
        while len(Variable5) < cities.shape[0]:
            Variable7, Variable8, Variable9 = get_closest(Variable8, cities,
                Variable5)
            Variable6 += Variable9
            Variable5.append(Variable7)
        Variable10 = calculate_something(Variable6, Variable5)
        if Variable6 < Variable2:
            Variable2 = Variable6
            Variable1 = Variable5
    return Variable1, Variable2


def Method2(city, cities, visited):
    Variable11 = float('inf')
    for Variable12, Variable13 in enumerate(cities):
        if Variable12 not in visited:
            Variable14 = dist_squared(city, Variable13)
            if Variable14 < Variable11:
                Variable15 = Variable13
                Variable16 = Variable12
                Variable11 = Variable14
    return Variable16, Variable15, Variable11


def Method3(c1, c2):
    Variable17 = c2[0] - c1[0]
    Variable18 = c2[1] - c1[1]
    return Variable17 ** 2 + Variable18 ** 2


def Method4(length, order):
    return Variable6 + len(Variable5)
