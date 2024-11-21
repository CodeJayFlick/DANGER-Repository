Here is the translation of the Java code to Python:

```Python
import unittest

class IExpressionOptimizerTest(unittest.TestCase):

    def setUp(self):
        self.expression_optimizer = ExpressionOptimizer()
        self.selected_series = []

    def test_time_only(self):
        try:
            time_filter = TimeFilter.lt(100)
            expression = GlobalTimeExpression(time_filter)
            print(self.expression_optimizer.optimize(expression, self.selected_series))

            or_expression = BinaryExpression.or_(
                BinaryExpression.and_(GlobalTimeExpression(TimeFilter.lt(50)), GlobalTimeExpression(TimeFilter.gt(10))),
                GlobalTimeExpression(TimeFilter.greater_than_or_equal_to(200))
            )

        except QueryFilterOptimizationException:
            self.fail()

    def test_series_only(self):
        try:
            filter1 = FilterFactory.and_(
                FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50)), TimeFilter.greater_than_or_equal_to(1400)
            )
            single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

            filter2 = FilterFactory.and_(
                FilterFactory.or_(ValueFilter.gt(100.5), ValueFilter.lt(50.6)), TimeFilter.greater_than_or_equal_to(1400)
            )
            single_series_exp2 = SingleSeriesExpression(Path("d1", "s2"), filter2)

            filter3 = FilterFactory.or_(
                FilterFactory.and_(ValueFilter.gt(100.5), ValueFilter.lt(50.6)), TimeFilter.greater_than_or_equal_to(1400)
            )
            single_series_exp3 = SingleSeriesExpression(Path("d2", "s2"), filter3)

            expression = BinaryExpression.and_(
                BinaryExpression.or_(single_series_exp1, single_series_exp2), single_series_exp3
            )

            self.assertEqual(expression.__str__(), self.expression_optimizer.optimize(expression, self.selected_series).__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_one_time_and_series(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        filter2 = FilterFactory.or_(ValueFilter.gt(100.5), ValueFilter.lt(50.6))
        single_series_exp2 = SingleSeriesExpression(Path("d1", "s2"), filter2)

        time_filter = TimeFilter.lt(14001234)
        global_time_filter = GlobalTimeExpression(time_filter)

        expression = BinaryExpression.and_(BinaryExpression.or_(single_series_exp1, single_series_exp2), global_time_filter)

        try:
            right_ret = "[[d2.s1:((value > 100 || value < 50) && time < 14001234)] || [d1.s2:((value > 100.5 || value < 50.6) && time < 14001234)]]"
            regular_filter = self.expression_optimizer.optimize(expression, self.selected_series)
            self.assertEqual(right_ret, regular_filter.__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_series_and_global_or_global(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        time_filter = TimeFilter.lt(14001234)
        global_time_filter = GlobalTimeExpression(time_filter)

        time_filter2 = TimeFilter.greater_than_or_equal_to(1)
        global_time_filter2 = GlobalTimeExpression(time_filter2)

        expression = BinaryExpression.or_(
            BinaryExpression.and_(single_series_exp1, global_time_filter), global_time_filter2
        )

        try:
            right_ret = "[[[d1.s1:time < 14001234] || [d2.s1:(time < 14001234 || (value > 100 || value < 50))]] || [d1.s2:(time < 14001234 || (value > 100.5 || value < 50.6))]] || [d2.s2:time < 14001234]]"
            regular_filter = self.expression_optimizer.optimize(expression, self.selected_series)
            self.assertEqual(right_ret, regular_filter.__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_series_and_global(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        time_filter = TimeFilter.lt(14001234)
        global_time_filter = GlobalTimeExpression(time_filter)

        expression = BinaryExpression.and_(single_series_exp1, global_time_filter)

        try:
            right_ret = "[[d2.s1:((value > 100 || value < 50) && time < 14001234)]]"
            regular_filter = self.expression_optimizer.optimize(expression, self.selected_series)
            self.assertEqual(right_ret, regular_filter.__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_one_time_or_series(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        filter2 = FilterFactory.or_(ValueFilter.gt(100.5), ValueFilter.lt(50.6))
        single_series_exp2 = SingleSeriesExpression(Path("d1", "s2"), filter2)

        time_filter = TimeFilter.lt(14001234)
        global_time_filter1 = GlobalTimeExpression(time_filter)
        global_time_filter2 = GlobalTimeExpression(TimeFilter.greater_than_or_equal_to(14001000))

        expression = BinaryExpression.or_(
            BinaryExpression.and_(global_time_filter1, global_time_filter2), 
            BinaryExpression.or_(single_series_exp1, single_series_exp2)
        )

        try:
            right_ret = "[[[d1.s1:(time < 14001234 && time > 14001000)] || [d2.s1:((value > 100 || value < 50) && (time < 14001234 && time > 14001000))]] || [d1.s2:((value > 100.5 || value < 50.6) && (time < 14001234 && time > 14001000))]] || [d2.s2:(time < 14001234 && time > 14001000)]]"
            regular_filter = self.expression_optimizer.optimize(expression, self.selected_series)
            self.assertEqual(right_ret, regular_filter.__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_two_time_combine(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        filter2 = FilterFactory.or_(ValueFilter.gt(100.5), ValueFilter.lt(50.6))
        single_series_exp2 = SingleSeriesExpression(Path("d1", "s2"), filter2)

        global_time_filter1 = GlobalTimeExpression(TimeFilter.lt(14001234))
        global_time_filter2 = GlobalTimeExpression(TimeFilter.greater_than_or_equal_to(14001000))

        expression = BinaryExpression.and_(
            BinaryExpression.or_(single_series_exp1, single_series_exp2), 
            BinaryExpression.and_(global_time_filter1, global_time_filter2)
        )

        try:
            right_ret = "[[[d2.s1:((value > 100 || value < 50) && (time < 14001234 && time > 14001000))]] || [d1.s2:((value > 100.5 || value < 50.6) && (time < 14001234 && time > 14001000))]]]"
            regular_filter = self.expression_optimizer.optimize(expression, self.selected_series)
            self.assertEqual(right_ret, regular_filter.__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_two_time_combine_expression(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        filter2 = FilterFactory.or_(ValueFilter.gt(100.5), ValueFilter.lt(50.6))
        single_series_exp2 = SingleSeriesExpression(Path("d1", "s2"), filter2)

        global_time_filter1 = GlobalTimeExpression(TimeFilter.lt(14001234))
        global_time_filter2 = GlobalTimeExpression(TimeFilter.greater_than_or_equal_to(14001000))

        expression = BinaryExpression.and_(
            BinaryExpression.or_(single_series_exp1, single_series_exp2), 
            BinaryExpression.and_(global_time_filter1, global_time_filter2)
        )

        try:
            right_ret2 = "[[d2.s1:((value > 100 || value < 50) && (time < 14001234 && time > 14001000)))] || [d1.s2:((value > 100.5 || value < 50.6) && (time < 14001234 && time > 14001000))]]"
            regular_filter = self.expression_optimizer.optimize(expression, self.selected_series)
            self.assertEqual(right_ret2, regular_filter.__str__())

        except QueryFilterOptimizationException:
            self.fail()

    def test_two_time_combine_expression_or(self):
        filter1 = FilterFactory.or_(ValueFilter.gt(100), ValueFilter.lt(50))
        single_series_exp1 = SingleSeriesExpression(Path("d2", "s1"), filter1)

        filter2 = FilterFactory.or_(ValueFilter.gt(100.5), ValueFilter.lt(50.6))
        single_series_exp2 = SingleSeriesExpression(Path("d1", "s2"), filter2)

        global_time_filter1 = GlobalTimeExpression(TimeFilter.lt(14001234))
        global_time_filter2 = GlobalTimeExpression(TimeFilter.greater_than_or_equal_to(14001000))

        expression = BinaryExpression.or_(
            expression, 
            BinaryExpression.and_(global_time_filter1, global_time_filter2)
        )

        try:
            self.expression_optimizer.optimize(expression, self.selected_series)

        except QueryFilterOptimizationException:
            self.fail()

if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code is not exactly equivalent to the Java code. The main differences are:

1. In Python, we don't need a `try` block for each expression optimization operation because exceptions will be caught by the test case.
2. We use `self.assertEqual()` instead of `Assert.assertEquals()`.
3. We define our own exception class (`QueryFilterOptimizationException`) in Java but it is not needed in Python as Python has its built-in exception handling mechanism.

Also, please note that this code does not include any actual implementation for the expression optimization logic. It only provides a basic structure to test different scenarios of filter expressions and their optimizations.