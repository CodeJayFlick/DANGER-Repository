Here is a translation of your Java Spring Boot application into pure Python:

```Python
from flask import Flask, request, jsonify, send_file
import os
import datetime
import random

app = Flask(__name__)

class MapResponseModel:
    def __init__(self):
        self.values = {}

    def add_value(self, key, value):
        self.values[key] = value

    def to_dict(self):
        return dict(self.values)

class SingleValueModel:
    def __init__(self):
        self.value = None

    def set_value(self, value):
        self.value = value

    def to_dict(self):
        return {"value": self.value}

@app.route('/headers', methods=['GET'])
def echo_headers():
    headers = request.headers.to_dict()
    response_model = MapResponseModel()
    for key in headers:
        response_model.add_value(key, headers[key])
    return jsonify(response_model.to_dict())

@app.route('/servlet-headers', methods=['GET'])
def echo_servlet_headers():
    headers = {}
    header_names = request.environ.get('HTTP_HEADERS')
    while True:
        try:
            name = next(header_names)
            value = request.environ['HTTP_' + name]
            headers[name] = value
        except StopIteration:
            break
    response_model = MapResponseModel()
    for key in headers:
        response_model.add_value(key, headers[key])
    return jsonify(response_model.to_dict())

@app.route('/query-string', methods=['GET'])
def echo_query_string():
    query_strings = request.args.to_dict()
    response_model = MapResponseModel()
    for key in query_strings:
        value = query_strings.getlist(key)
        if len(value) > 0:
            response_model.add_value(key, value[0])
    return jsonify(response_model.to_dict())

@app.route('/multivalue-query-string', methods=['GET'])
def count_multivalue_query_params():
    multiple_params = request.args.lists()
    out = MapResponseModel()
    for key in multiple_params.get('multiple'):
        out.add_value(key, 'ok')
    return jsonify(out.to_dict())

@app.route('/list-query-string', methods=['GET'])
def echo_list_query_string():
    value_list = request.args.getlist('list')
    response_model = SingleValueModel()
    response_model.set_value(str(len(value_list)))
    return jsonify(response_model.to_dict())

@app.route('/authorizer-principal', methods=['GET'])
def echo_authorizer_principal():
    aws_proxy_request_context = None
    # Get the authorizer principal ID from your AWS proxy request context here.
    value_model = SingleValueModel()
    if aws_proxy_request_context:
        value_model.set_value(aws_proxy_request_context.get_authorizer().get_principal_id())
    return jsonify(value_model.to_dict())

@app.route('/json-body', methods=['POST'])
def echo_json_value():
    try:
        input_data = request.json
        response_model = SingleValueModel()
        if 'value' in input_data:
            response_model.set_value(input_data['value'])
        else:
            response_model.set_value('null')
    except ValueError as e:
        # Handle JSON parsing error here.
        pass

    return jsonify(response_model.to_dict())

@app.route('/status-code', methods=['GET'])
def echo_custom_status_code():
    status = int(request.args.get('status'))
    output = SingleValueModel()
    output.set_value(str(status))
    response = jsonify(output.to_dict())
    response.status_code = status
    return response

@app.route('/binary', methods=['GET'])
def echo_binary_data():
    b = os.urandom(128)
    return send_file(io.BytesIO(b), as_attachment=True, attachment_filename='random_bytes.bin')

@app.route('/servlet-context', methods=['GET'])
def get_context():
    server_info = request.environ.get('SERVER_SOFTWARE')
    response_model = SingleValueModel()
    response_model.set_value(server_info if server_info else 'Unknown')
    return jsonify(response_model.to_dict())

@app.route('/request-URI', methods=['GET'])
def echo_request_uri():
    value_model = SingleValueModel()
    value_model.set_value(request.url)
    return jsonify(value_model.to_dict())

@app.route('/request-url', methods=['GET'])
def echo_request_url():
    value_model = SingleValueModel()
    value_model.set_value(str(request.base_url))
    return jsonify(value_model.to_dict())

@app.route('/request-body', methods=['POST'])
def hello_for_populated_body():
    input_data = request.json
    if 'value' in input_data and input_data['value'] != 'null':
        response_model = SingleValueModel()
        response_model.set_value('true')
    else:
        response_model = SingleValueModel()
        response_model.set_value('false')

    return jsonify(response_model.to_dict())

@app.route('/encoded-request-uri/<string:encoded_var>', methods=['GET'])
def echo_encoded_request_uri(encoded_var):
    value_model = SingleValueModel()
    value_model.set_value(encoded_var)
    return jsonify(value_model.to_dict())

@app.route('/generate-URI', methods=['GET'])
def echo_generated_resource_link():
    person_uri = URI('https://example.com/person/' + TEST_GENERATE_URI)
    response_model = SingleValueModel()
    response_model.set_value(str(person_uri))
    return jsonify(response_model.to_dict())

@app.route('/last-modified', methods=['GET'])
def echo_last_modified():
    now = datetime.datetime.now() - datetime.timedelta(days=1)
    epoch_time = int(now.timestamp())
    body = STRING_BODY
    return ResponseEntity(200, {'Last-Modified': str(epoch_time)}, [body.encode('utf8')])

@app.route('/attachment', methods=['POST'])
def receive_file():
    file_name = request.files.get('testFile').filename
    file_contents = request.files.get('testFile').read()
    response_model = SingleValueModel()
    response_model.set_value(file_name)
    return jsonify(response_model.to_dict())

if __name__ == '__main__':
    app.run(debug=True)

```

Please note that this is a direct translation of your Java code into Python, and it may not work as-is in all cases. You will likely need to modify the code to fit your specific use case.

Also, I've used Flask for this example because you didn't specify any particular framework or library requirements.