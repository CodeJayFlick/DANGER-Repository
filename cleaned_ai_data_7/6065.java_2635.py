import unittest


class CParserUtilsTest(unittest.TestCase):

    def test_user_message_on_token_mgr_error(self):
        function = "void bob@12(int a)"
        try:
            self.parse_function(function)
        except Exception as e:
            message = handle_parse_problem(e, function)

        character_info = "near character 8"
        invalid_info = "<font color=\"red\"><b>@"

        self.assertIn(character_info, message)
        self.assertIn(invalid_info, message)


    def test_user_message_on_parse_exception(self):
        function = "void bob(int a)()"
        try:
            self.parse_function(function)
        except Exception as e:
            message = handle_parse_problem(e, function)

        character_info = "near character 17"

        self.assertIn(character_info, message)


    def parse_function(self, function):
        parser = CParser()
        try:
            parser.parse(function)
        except Exception:
            raise


    @staticmethod
    def handle_parse_problem(problem, function):
        return str(problem) + f" near {function}"


if __name__ == "__main__":
    unittest.main()
