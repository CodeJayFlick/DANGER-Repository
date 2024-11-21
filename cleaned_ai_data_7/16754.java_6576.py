class CustomizedJsonPayloadFormatter:
    def format(self, payload):
        if not payload:
            return []

        import json
        from typing import List

        # Suppose the payload is a json format
        data = json.loads(payload.decode('utf-8'))

        ret = []
        for i in range(2):
            ts = i
            message = {'device': f'd{i}', 'timestamp': ts, 'measurements': ['s1', 's2'], 'values': [f'4.0{i}', f'5.0{i}']}
            ret.append(message)

        return ret

    def get_name(self):
        return "CustomizedJson"
