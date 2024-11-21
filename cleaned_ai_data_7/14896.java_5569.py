import logging
from typing import Dict, Any

class LambdaInfoApiHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.SUCCESS_STATUS_CODE = 200

    def handle_request(self, input: Dict[str, Any], context: Any) -> dict:
        self.logger.info("received: " + str(input))

        lambda_info = self.lambda_info(context)
        return {
            'statusCode': self.SUCCESS_STATUS_CODE,
            'headers': {'Content-Type': 'application/json'},
            'body': lambda_info
        }

    def lambda_info(self, context: Any) -> dict:
        lambda_info = {}
        lambda_info['aws_request_id'] = context.get('aws_request_id')
        lambda_info['function_name'] = context.get('function_name')
        lambda_info['function_version'] = context.get('function_version')
        lambda_info['log_group_name'] = context.get('log_group_name')
        lambda_info['log_stream_name'] = context.get('log_stream_name')
        lambda_info['memory_limit_in_mb'] = context.get('memory_limit_in_mb')

        return lambda_info

# Usage
handler = LambdaInfoApiHandler()
input_data = {'key': 'value'}
context = {'aws_request_id': '123', 'function_name': 'my_function', ...}
response = handler.handle_request(input_data, context)
print(response)
