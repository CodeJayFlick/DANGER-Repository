Here is the equivalent Python code for the given Java file:

```Python
import unittest
from unittest.mock import patch, Mock
from json import dumps, loads

class SavePersonApiHandlerTest(unittest.TestCase):

    def setUp(self):
        self.save_person_api_handler = SavePersonApiHandler()
        self.dynamo_db_mapper = Mock()

    @patch('dynamodbv2.DynamoDBMapper')
    def test_handle_request_save_person_successful(self, mock_dynamo_db_mapper):
        person = Person("Thor", "Odinson")
        address = Address("1 Odin ln", "Asgard", "country of the Gods", "00001")
        person.set_address(address)
        
        request_body = dumps({'firstName': 'Thor', 'lastName': 'Odinson', 
                              'address': {'AddressLineOne': '1 Odin ln', 'City': 'Asgard', 
                                          'State': 'country of the Gods', 'ZipCode': '00001'}})

        request_event = APIGatewayProxyRequestEvent(request_body)
        
        with patch('lambda.runtime.Context') as mock_context:
            response_event = self.save_person_api_handler.handle_request(request_event, mock_context())
            
            self.dynamo_db_mapper.save.assert_called_once_with(person)
            self.assertIsNotNone(response_event)
            self.assertEqual(201, response_event.status_code)

    @patch('dynamodbv2.DynamoDBMapper')
    def test_handle_request_save_person_exception(self):
        request_body = dumps({'invalid': 'request'})
        
        request_event = APIGatewayProxyRequestEvent(request_body)
        
        with patch('lambda.runtime.Context') as mock_context:
            response_event = self.save_person_api_handler.handle_request(request_event, mock_context())
            
            self.assertIsNotNone(response_event)
            self.assertEqual(400, response_event.status_code)

class Person:
    def __init__(self, first_name, last_name):
        self.first_name = first_name
        self.last_name = last_name

    def set_address(self, address):
        self.address = address


class Address:
    def __init__(self, address_line_one, city, state, zip_code):
        self.AddressLineOne = address_line_one
        self.City = city
        self.State = state
        self.ZipCode = zip_code

class APIGatewayProxyRequestEvent:
    def with_body(self, body):
        return {'body': body}

if __name__ == '__main__':
    unittest.main()
```

Note: This Python code is not a direct translation of the Java code. It's an equivalent implementation in Python using its own syntax and libraries (e.g., `unittest`, `json`).