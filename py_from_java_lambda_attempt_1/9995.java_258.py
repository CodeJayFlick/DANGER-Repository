Here is the equivalent Python code:

```Python
class DefaultDropDownSelectionDataModelTest:
    def __init__(self):
        pass

    @staticmethod
    def setUp():
        data = [{"name": "abc"}, {"name": "baa"}, {"name": "bac"}, {"name": "bace"}, {"name": "bad"}, {"name": "cat"}, {"name": "zzz"}]
        model = DefaultDropDownSelectionDataModel(data, lambda x: x["name"])
        return data, model

    @staticmethod
    def test_get_matching_data(model):
        matching_data = model.getMatchingData("a")
        assert len(matching_data) == 1 and matching_data[0]["name"] == "abc"

        matching_data = model.getMatchingData("bac")
        assert len(matching_data) == 2 and matching_data[0]["name"] == "bac" and matching_data[1]["name"] == "bace"


class DefaultDropDownSelectionDataModel:
    def __init__(self, data, get_name):
        self.data = data
        self.get_name = get_name

    def getMatchingData(self, query):
        return [item for item in self.data if self.get_name(item).startswith(query)]


if __name__ == "__main__":
    test_data, model = DefaultDropDownSelectionDataModelTest().setUp()
    DefaultDropDownSelectionDataModelTest.test_get_matching_data(model)
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@Test`. In the above code, I've used static methods to simulate these. Also, Python is dynamically typed so you don't need explicit type definitions like in Java.