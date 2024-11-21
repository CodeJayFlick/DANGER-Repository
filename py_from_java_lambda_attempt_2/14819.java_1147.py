Here is the translation of the Java code to Python:

```Python
import unittest
from django.test import TestCase
from django.db.models import Q
from your_app.models import Person  # Replace 'your_app' with your actual app name


class RepositoryTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.peter = Person(name="Peter", surname="Sagan", age=17)
        cls.nasta = Person(name="Nasta", surname="Kuzminova", age=25)
        cls.john = Person(name="John", surname="Lawrence", age=35)
        cls.terry = Person(name="Terry", surname="Law", age=36)

    def setUp(self):
        self.peter.save()
        self.nasta.save()
        self.john.save()
        self.terry.save()

    def test_find_all(self):
        actuals = list(Person.objects.all())
        self.assertTrue(set(actuals).issuperset({self.peter, self.nasta, self.john, self.terry}))

    def test_save(self):
        terry = Person.objects.get(name="Terry")
        terry.surname = "Lee"
        terry.age = 47
        terry.save()

        self.assertEqual(terry.surname, "Lee")
        self.assertEqual(terry.age, 47)

    def test_delete(self):
        terry = Person.objects.get(name="Terry")
        terry.delete()

        self.assertEqual(Person.objects.count(), 3)
        self.assertRaises(ObjectDoesNotExist, lambda: Person.objects.get(name="Terry"))

    def test_count(self):
        self.assertEqual(Person.objects.count(), 4)

    def test_find_all_by_age_between_spec(self):
        persons = list(Person.objects.filter(age__range=(20, 40)))
        self.assertEqual(len(persons), 3)
        for person in persons:
            self.assertGreaterEqual(person.age, 20)
            self.assertLessEqual(person.age, 40)

    def test_find_one_by_name_equal_spec(self):
        actual = Person.objects.get(name="Terry")
        self.assertIsNotNone(actual)
        self.assertEqual(actual, self.terry)

    @classmethod
    def tearDownClass(cls):
        cls.peter.delete()
        cls.nasta.delete()
        cls.john.delete()
        cls.terry.delete()


if __name__ == '__main__':
    unittest.main()
```

Please note that you need to replace `'your_app'` with your actual app name in the `from your_app.models import Person` line, and also make sure that you have a Django project set up correctly for this code to run.