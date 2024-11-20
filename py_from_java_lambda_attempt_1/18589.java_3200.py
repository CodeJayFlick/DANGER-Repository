Here is the equivalent Python code:

```Python
import json

class ApiGatewayAuthorizerContextTest:
    FIELD_NAME_1 = "CUSTOM_FIELD_1"
    FIELD_NAME_2 = "CUSTOM_FIELD_2"
    FIELD_VALUE_1 = "VALUE_1"
    FIELD_VALUE_2 = "VALUE_2"
    PRINCIPAL = "xxxxx"

    AUTHORIZER_REQUEST = json.dumps({
        "resource": "/restaurants",
        "path": "/restaurants",
        "httpMethod": "GET",
        "headers": {
            "Accept": "*/*",
            "Authorization": "eyJraWQiOiJKSm9VQUtrRThcL3NTU3Rwa3dPZTFWN2dvak1xS0k1NU8zTzB4WVgwMGNRdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0MmRmM2IwMi0yOWYxLTQ3NzktYTNlNS1lZmY5MmZmMjgwYjIiLCJhdWQiOiIyazNubzJqMXJqamJxYXNrYzRiazB1YjI5YiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTQ5MjQ2NzE2OSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMi5hbWF6b25hd3MuY29tXC91cy1lYXN0LTJfQWR4NVpIZVBnIiwiY29nbml0bzp1c2VybmFtZSI6InNhcGVzc2kiLCJleHAiOjE0OTI0NzA3NjksImlhdCI6MTQ5MjQ2NzE2OSwiZW1haWwiOiJidWxpYW5pc0BhbWF6b24uY29tIn0.eyJraWQiOiJKSm9VQUtrRThcL3NTU3Rwa3dPZTFWN2dvak1xS0k1NU8zTzB4WVgwMGNRdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0MmRmM2IwMi0yOWYxLTQ3NzktYTNlNS1lZmY5MmZmMjgwYjIiLCJhdWQiOiIyazNubzJqMXJqamJxYXNrYzRiazB1YjI5YiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTQ5MjQ2NzE2OSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMi5hbWF6b25hd3MuY29tXC91cy1lYXN0LTJfQWR4NVpIZVBnIiwiY29nbml0bzp1c2VybmFtZSI6InNhcGVzc2kiLCJleHAiOjE0OTI0NzA3NjksImlhdCI6MTQ5MjQ2NzE2OSwiZW1haWwiOiJidWxpYW5pc0BhbWF6b24uY29tIn0.aTODUMNib_pQhad1aWTHrlz7kwA5QkcvZptcbLFY5BuNqpr9zsK14EhHRvmvflK4MMQaxCE5Cxa9joR9g-HCmmF1usZhXO4Q2iyEWcBk0whjn3CnC55k6yEuMv6y9krts0YHSamsRkhW7wnCpuLmk2KgzHTfyt6oQ1qbg9QE8l9LRhjCHLnujlLIQaG9p9UfJVf-uGSg1k_",
            "CloudFront-Forwarded-Proto": "https"
        },
        "queryStringParameters": None,
        "pathParameters": None,
        "stageVariables": None,
        "requestContext": {
            "accountId": "XXXXXXXXXXXXXX",
            "resourceId": "xxxxx",
            "stage": "dev",
            "authorizer": {
                "principalId": PRINCIPAL,
                FIELD_NAME_1: FIELD_VALUE_1,
                FIELD_NAME_2: FIELD_VALUE_2
            },
            "requestId": "ad0a33ba-23bc-11e7-9b7d-235a67eb05bd",
            "identity": {
                "cognitoIdentityPoolId": None,
                "accountId": None,
                "cognitoIdentityId": None,
                "caller": None,
                "apiKey": None,
                "sourceIp": "54.240.196.171",
                "accessKey": None,
                "cognitoAuthenticationType": None,
                "cognitoAuthenticationProvider": None,
                "userArn": None,
                "userAgent": "PostmanRuntime/3.0.1",
                "user": None
            },
            "resourcePath": "/restaurants",
            "httpMethod": "GET",
            "apiId": "xxxxxxxx"
        },
        "body": None,
        "isBase64Encoded": False
    })

    def test_authorizer_context_serialize_custom_values(self):
        try:
            req = json.loads(AUTHORIZER_REQUEST)
            assert req["requestContext"]["authorizer"].get(FIELD_NAME_1) is not None
            assert req["requestContext"]["authorizer"].get(FIELD_NAME_2) is not None
            assert req["requestContext"]["authorizer"][FIELD_NAME_1] == FIELD_VALUE_1
            assert req["requestContext"]["authorizer"][FIELD_NAME_2] == FIELD_VALUE_2
            assert req["requestContext"]["authorizer"]["principalId"] == PRINCIPAL
        except Exception as e:
            print(str(e))
            self.fail()
```

Please note that this is a direct translation of the Java code to Python, and it may not be perfect. The `test_authorizer_context_serialize_custom_values` method in the above code does exactly what its counterpart does: tests if custom values are serialized correctly in an API Gateway authorizer context.