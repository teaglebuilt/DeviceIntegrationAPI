from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin


app = Flask(__name__)

app.config.from_pyfile('config.py')

db = SQLAlchemy(app)

admin = Admin(app)

from views import *

if __name__ == '__main__':
    app.run(debug=True, port=8080)

