import json

class AwsHttpApiV2SecurityContextWriter:
    def write_security_context(self, event: dict, lambda_context: dict) -> dict:
        return {"lambda_context": lambda_context, "event": event}

# Example usage
if __name__ == "__main__":
    event = {"key1": "value1", "key2": "value2"}
    lambda_context = {"function_name": "my_function", "invoked_function_arn": "arn:aws:lambda:us-west-2:123456789012:function:my-function"}
    security_context = AwsHttpApiV2SecurityContextWriter().write_security_context(event, lambda_context)
    print(json.dumps(security_context))
