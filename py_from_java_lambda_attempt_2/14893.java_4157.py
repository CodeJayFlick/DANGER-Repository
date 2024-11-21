Here is the equivalent Python code:

```Python
import logging
from json import loads, dumps
from boto3.dynamodb.conditions import Key

class SavePersonApiHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.created_status_code = 201
        self.bad_request_status_code = 400

    def handle_request(self, event, context):
        try:
            person = loads(event['body'])
            dynamodb = boto3.resource('dynamodb')
            table_name = 'persons'
            table = dynamodb.Table(table_name)
            table.put_item(Item=person)
            return {
                'statusCode': self.created_status_code,
                'body': dumps(person),
                'headers': {'Content-Type': 'application/json'}
            }
        except Exception as e:
            self.logger.error('unable to parse body', e)
            return {
                'statusCode': self.bad_request_status_code,
                'body': '',
                'headers': {'Content-Type': 'application/json'}
            }

# usage
handler = SavePersonApiHandler()
event = {'body': '{"name": "John", "age": 30}'}
context = None
response = handler.handle_request(event, context)
print(response)
```

Please note that this code assumes you have the necessary AWS credentials set up and boto3 installed. It also doesn't include any error handling for DynamoDB operations (e.g., what if the table or item already exists?).