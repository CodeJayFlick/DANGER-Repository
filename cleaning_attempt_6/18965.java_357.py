import requests

class TestSinglePageApplicationRouting:
    def test_make_sure_non_home_path_serves_html(self):
        response = requests.get("http://localhost/tree/123")
        self.assertEqual(response.headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
