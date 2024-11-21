Here is the equivalent Python code:
```
import json
from aws_lambda import lambda_handler

def ping(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Pong!'})
    }

lambda_handler(ping)
```
Note that this is a very simplified version of the original Java code. The Python AWS Lambda handler function `ping` simply returns a JSON response with a status code of 200 and a message.

In contrast to the Java code, which uses Jersey and Jackson for handling HTTP requests and responses, the Python code relies on the built-in `json` module for serializing and deserializing data. The `lambda_handler` function is also not present in the original Java code; it's a part of AWS Lambda that allows you to define your handler function.

Also note that this Python code does not implement the same functionality as the original Java code, which uses Amazon Web Services (AWS) services like Lambda and API Gateway. This Python code only defines a simple lambda function that returns a JSON response.