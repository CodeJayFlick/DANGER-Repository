Here is the translation of the Java code to Python:

```Python
class AwsProxyHttpServletResponseWriter:
    def __init__(self):
        self.write_single_value_headers = False

    def write_response(self, container_response: dict, lambda_context: dict) -> dict:
        aws_proxy_response = {}
        
        if 'aws_response_body_string' in container_response and container_response['aws_response_body_string'] is not None:
            response_string = container_response['aws_response_body_string']
            
            content_type = container_response.get('content_type', '')
            if not self.is_binary(content_type) and self.is_valid_utf8(container_response.get('aws_response_bytes')):
                aws_proxy_response['body'] = response_string
            else:
                response_string = base64.b64encode(container_response['aws_response_bytes']).decode()
                aws_proxy_response['base_64_encoded'] = True
            
        if 'aws_response_headers' in container_response and isinstance(container_response.get('aws_response_headers'), dict):
            aws_proxy_response['multi_value_headers'] = container_response['aws_response_headers']
        
        if self.write_single_value_headers:
            aws_proxy_response['headers'] = self.to_single_value_headers(container_response.get('aws_response_headers'))
        
        aws_proxy_response['status_code'] = container_response.get('status', 200)
        
        request_source = container_response.get('request_source')
        if request_source == 'ALB':
            aws_proxy_response['status_description'] = f"{container_response.get('status')} {Response.Status.from_status_code(container_response.get('status')).reason_phrase}"
        
        return aws_proxy_response

    def to_single_value_headers(self, headers: dict) -> dict:
        out = {}
        if not headers or len(headers) == 0:
            return out
        
        for key in headers.keys():
            out[key] = headers.get(key)
        
        return out
    
    def is_binary(self, content_type: str) -> bool:
        if content_type:
            semidx = content_type.index(';') if ';' in content_type else -1
            if semidx >= 0:
                return LambdaContainerHandler().get_container_config().is_binary_content_type(content_type[:semidx])
            else:
                return LambdaContainerHandler().get_container_config().is_binary_content_type(content_type)
        return False
    
    def is_valid_utf8(self, aws_response_bytes: bytes) -> bool:
        # This method seems to be missing in the Java code. It's not clear what it should do.
        pass
```

Please note that I've made some assumptions about the Python equivalent of certain Java classes and methods (like `Response.Status`), as they are not provided in the original code.