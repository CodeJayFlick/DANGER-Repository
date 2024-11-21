from flask_security import Security, login_required, current_user
from flask_httpauth import HTTPBasicAuth
import bcrypt

class User:
    def __init__(self, username):
        self.username = username

class UserDetails(User):
    pass

security = Security()

@security.user_loader
def load_user(username):
    if username == 'admin':
        return UserDetails('admin')
    else:
        return None

app.config['SECRET_KEY'] = 'my_secret_key'

@app.route('/')
@login_required
def index():
    return "Hello, {}!".format(current_user.username)

if __name__ == '__main__':
    app.run(debug=True)
