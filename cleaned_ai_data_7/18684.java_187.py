import json
from aws_lambda import lambda_handler

def ping(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Pong!'})
    }

lambda_handler(ping)
