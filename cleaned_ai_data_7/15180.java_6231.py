class SoldierTest:
    def __init__(self):
        pass  # equivalent to super(Soldier::new)

    def verify_visit(self, unit: 'Soldier', mocked_visitor) -> None:
        import unittest.mock as mockito

        mockito.verify(mocked_visitor).visit_soldier(eq(unit))
