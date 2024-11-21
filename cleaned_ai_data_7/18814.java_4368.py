import unittest
from unittest.mock import patch, Mock
from typing import Dict, Set

class TestBearerAuthenticationProvider(unittest.TestCase):
    def test_null_params(self):
        with self.assertRaises(NullPointerException):
            provider().build(None)

    @patch('org.projectnessie.client.http.HttpClient.register')
    def test_from_config(self, mock_register):
        auth_cfg = {'CONF_NESSIE_AUTH_TYPE': 'Bearer', 
                    CONF_NESSIE_AUTH_TOKEN: 'token123'}
        
        authentication = NessieAuthenticationProvider.from_config(auth_cfg.get)
        self.check_auth(authentication)

    @patch('org.projectnessie.client.http.HttpClient.register')
    def test_static_builder(self, mock_register):
        self.check_auth(BearerAuthenticationProvider.create('token123'))

    def check_auth(self, authentication: HttpAuthentication) -> None:
        self.assertIsInstance(authentication, HttpAuthentication)
        
        http_authentication = cast(HttpAuthentication, authentication)

        auth_filter = []
        client = Mock()
        with patch.object(client, 'register') as mock_register:
            def side_effect(request_filter):
                if request_filter is not None and isinstance(request_filter, RequestFilter):
                    auth_filter.append(request_filter)
                return None
            mock_register.side_effect = side_effect

            http_authentication.apply_to_http_client(client)

        self.assertIsInstance(auth_filter[0], RequestFilter)

        map: Dict[str, Set[str]] = {}
        context = RequestContext(map, None, None, None)
        auth_filter[0].filter(context)

        self.assertIn('Authorization', map)
        self.assertEqual(set(map['Authorization']), {'Bearer token123'})


if __name__ == '__main__':
    unittest.main()
