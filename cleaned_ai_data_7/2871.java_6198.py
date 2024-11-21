import unittest

class A:
    pass


class B(A):
    def __init__(self, a: 'A'):
        self.a = a


class C(A):
    def __init__(self, a: 'A'):
        self.a = a


class D(B, C):
    def __init__(self, b: 'B', c: 'C'):
        super().__init__()
        self.b = b
        self.c = c


class NeedsInjectionNoExtends:
    def __init__(self):
        DependentServiceResolver.inject(self)

    @property
    def d(self) -> D:
        return D(B(A()), C(A()))

    @property
    def a(self) -> A:
        return A()

    @property
    def b(self) -> B:
        return self.d.b

    @property
    def c(self) -> C:
        return self.d.c


class TestNeedsInjectionNoExtends(unittest.TestCase):
    def test_no_extends(self):
        needs = NeedsInjectionNoExtends()
        self.assertEqual(needs.c, needs.d.c)
        self.assertEqual(needs.b, needs.d.b)
        self.assertEqual(needs.a, needs.c.a)
        self.assertEqual(needs.a, needs.b.a)


class E:
    pass


class D2(D):
    def __init__(self, b: 'B', c: 'C', e: 'E'):
        super().__init__(b, c)
        self.e = e


class F:
    def __init__(self, d: 'D', d2: 'D2'):
        self.d = d
        self.d2 = d2


class NeedsInjectionOverrideD(NeedsInjectionNoExtends):
    def __init__(self):
        super().__init__()

    @property
    def e(self) -> E:
        return E()

    @property
    def f(self) -> F:
        return F(D(B(A()), C(A())), D2(B(A()), C(A()), self.e))


class TestNeedsInjectionOverrideD(unittest.TestCase):
    def test_override_d(self):
        needs = NeedsInjectionOverrideD()
        self.assertEqual(needs.c, needs.d.c)
        self.assertEqual(needs.b, needs.d.b)
        self.assertEqual(needs.a, needs.c.a)
        self.assertEqual(needs.a, needs.b.a)

        self.assertTrue(isinstance(needs.d, D2))
        self.assertEqual(needs.e, (needs.d).e)
        self.assertEqual(needs.d, needs.f.d)
        self.assertEqual(needs.d, needs.f.d2)


class MyException(Exception):
    pass


class NeedsInjectionExceptionThrower:
    def __init__(self):
        DependentServiceResolver.inject(self)

    @property
    def a(self) -> A:
        raise MyException()


class TestNeedsInjectionExceptionThrower(unittest.TestCase):
    def test_exception(self):
        try:
            needs = NeedsInjectionExceptionThrower()
        except Exception as e:
            self.assertEqual(type(e), MyException)


class NeedsInjectionTwoStepExceptionThrower:
    def __init__(self):
        DependentServiceResolver.inject(self)

    @property
    def b(self) -> B:
        return new_b(A())

    @property
    def a(self) -> A:
        raise MyException()


def new_b(a: 'A') -> B:
    return B(a)


class TestNeedsInjectionTwoStepExceptionThrower(unittest.TestCase):
    def test_two_step_exception(self):
        try:
            needs = NeedsInjectionTwoStepExceptionThrower()
        except Exception as e:
            self.assertEqual(type(e), MyException)


class UnsatisfiedParameter:
    def __init__(self):
        DependentServiceResolver.inject(self)

    @property
    def b(self) -> B:
        return new_b(A())


def new_b(a: 'A') -> B:
    return B(a)


class TestUnsatisfiedParamter(unittest.TestCase):
    def test_unsatisfied_paramter(self):
        needs = UnsatisfiedParameter()


class UnsatisfieldField:
    def __init__(self):
        DependentServiceResolver.inject(self)

    @property
    def a(self) -> A:
        return A()


class TestUnsatisfiedField(unittest.TestCase):
    def test_unsatisfied_field(self):
        needs = UnsatisfieldField()
