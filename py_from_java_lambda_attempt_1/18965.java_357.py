Here is the translation of the Java code to Python:
```
import requests

class TestSinglePageApplicationRouting:
    def test_make_sure_non_home_path_serves_html(self):
        response = requests.get("http://localhost/tree/123")
        self.assertEqual(response.headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
```
Note that I used the `requests` library to make a GET request and check the response headers and status code. I also assumed that you want to use Python's built-in testing framework, `unittest`. If you prefer another testing framework, such as Pytest or Behave, let me know!