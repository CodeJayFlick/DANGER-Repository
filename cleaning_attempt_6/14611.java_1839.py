import unittest
from hamcrest import assert_that, contains_string

class SimpleObjectsIntegTest(unittest.TestCase):

    def setUp(self):
        self.fixture_scripts = RecreateSimpleObjects()
        self.simple_objects = SimpleObjects()

    def test_list_all(self):
        # Given
        self.fixture_scripts.run_fixture_script(None)
        next_transaction()

        # When
        all = self.simple_objects.list_all()

        # Then
        assert_that(len(all), equal_to(len(self.fixture_scripts.get_simple_objects())))

        simple_object = all[0]
        assert_that(simple_object.name, equal_to(self.fixture_scripts.get_simple_objects()[0].name))

    def test_list_all_when_none(self):
        # Given
        self.fixture_scripts = SimpleObjectsTearDown()
        self.fixture_scripts.run_fixture_script(None)
        next_transaction()

        # When
        all = self.simple_objects.list_all()

        # Then
        assert_that(len(all), equal_to(0))

    def test_create(self):
        # Given
        self.fixture_scripts = SimpleObjectsTearDown()
        self.fixture_scripts.run_fixture_script(None)
        next_transaction()

        # When
        self.simple_objects.create("Faz")

        # Then
        all = self.simple_objects.list_all()
        assert_that(len(all), equal_to(1))

    def test_create_when_already_exists(self):
        # Given
        self.fixture_scripts = SimpleObjectsTearDown()
        self.fixture_scripts.run_fixture_script(None)
        next_transaction()

        # When
        self.simple_objects.create("Faz")
        next_transaction()

        try:
            self.simple_objects.create("Faz")
        except SQLIntegrityConstraintViolationException as e:
            pass

    def causal_chain_contains(cls):
        return lambda item: contains_string(f"exception with causal chain containing {cls.__name__}")

if __name__ == '__main__':
    unittest.main()
