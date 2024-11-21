Here is the equivalent Python code:

```Python
import jwt
from datetime import datetime, timedelta

def generate_token():
    token1 = {
        'iss': 'http://nessie.dremio.com',
        'upn': 'admin_user',
        'groups': ['user', 'admin'],
        'birthdate': '2001-07-13T00:00:00Z',
        'exp': int(datetime.utcnow().replace(tzinfo=datetime.timezone.utc) + timedelta(days=365).utctimetuple())
    }
    
    token = jwt.encode(token1, 'your_secret_key', algorithm='HS256')
    print(token.decode('utf-8'))

def generate_token2():
    token2 = {
        'iss': 'https://quarkus.io/using-jwt-rbac',
        'upn': 'test_user',
        'groups': ['user'],
        'birthdate': '2001-07-13T00:00:00Z',
        'exp': int(datetime.utcnow().replace(tzinfo=datetime.timezone.utc) + timedelta(days=365).utctimetuple())
    }
    
    token = jwt.encode(token2, 'your_secret_key', algorithm='HS256')
    print(token.decode('utf-8'))

if __name__ == "__main__":
    generate_token()
    generate_token2()
```

Please note that you need to install the `pyjwt` library and replace `'your_secret_key'` with your actual secret key.