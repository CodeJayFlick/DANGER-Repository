Here is the equivalent Python code:

```Python
import unittest
from typing import List, Tuple

class TSPlanContextAuthorTest(unittest.TestCase):

    def setUp(self):
        self.empty_paths = []
        self.test_paths = [("root.node1.a", "b")]

    def test_analyze_author(self) -> None:
        for input_sql, paths in [
            ("CREATE USER username1 'password1'", self.empty_paths),
            ("DROP USER username", self.empty_paths),
            ("CREATE ROLE rolename", self.empty_paths),
            ("DROP ROLE rolename", self.empty_paths),
            (
                "GRANT USER username PRIVILEGES SET_STORAGE_GROUP,INSERT_TIMESERIES ON root.node1.a.b",
                self.test_paths
            ),
            (
                "REVOKE USER username PRIVILEGES SET_STORAGE_GROUP,INSERT_TIMESERIES ON root.node1.a.b",
                self.test_paths
            ),
            (
                "GRANT ROLE rolename PRIVILEGES SET_STORAGE_GROUP,INSERT_TIMESERIES ON root.node1.a.b",
                self.test_paths
            ),
            (
                "REVOKE ROLE rolename PRIVILEGES SET_STORAGE_GROUP,INSERT_TIMESERIES ON root.node1.a.b",
                self.test_paths
            ),
            ("GRANT rolename TO username", self.empty_paths),
            ("REVOKE rolename FROM username", self.empty_paths)
        ]:
            planner = Planner()
            author_plan = planner.parse_sql_to_physical_plan(input_sql)
            if author_plan is None:
                raise unittest.SkipTest("Author plan not found")
            self.assertEqual(paths, [path for path in author_plan.get_paths()])

if __name__ == "__main__":
    unittest.main()
```

Note that Python does not have direct equivalent of Java's `@RunWith` and `@Parameters`, so we use the built-in support for test suites with multiple tests. Also, Python has no concept of static methods or variables like in Java, but it supports class-level attributes which are similar to them.