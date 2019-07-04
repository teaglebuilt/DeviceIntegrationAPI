from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid, jwt, datetime
from functools import wraps
from os import environ

app = Flask(__name__)

app.config['SECRET_KEY'] = environ.get('SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DB_PATH')

db = SQLAlchemy(app)


class Organization(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    public_id       = db.Column(db.String(50), unique=True)
    name            = db.Column(db.String(50))
    device          = db.relationship('Device', backref='organization', lazy='dynamic')
    password        = db.Column(db.String(80))
    admin           = db.Column(db.Boolean)

class Device(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(50), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Organization.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/organizations', methods=['GET'])
@token_required    
def get_all_organizations(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'This endpoint is not allowed!'})

    qs = db.session.query(Organization).all()
    print(qs)
    output = [] 
    for org in qs:
        print(org)
        org_data = {}
        org_data['public_id'] = str(org.public_id)
        org_data['name'] = org.name
        org_data['password'] = org.password
        org_data['admin'] = org.admin
        output.append(org_data)

    print(output)
    return jsonify({"organizations": output})

@app.route('/organization/<public_id>', methods=['GET'])
@token_required 
def get_one_organization(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'This endpoint is not allowed!'})

    qs = Organization.query.filter_by(public_id=public_id).first()
    if not qs:
        return jsonify({"message": "No Organization Found."})

    org_data = {}
    org_data['public_id'] = org.public_id
    org_data['name'] = org.name
    org_data['password'] = org.password
    org_data['admin'] = org.admin
    return jsonify({"organization": org_data})
    

# @app.route('/organization', methods=['POST'])
# @token_required 
def create_organization(current_user):
    # if not current_user.admin:
    #     return jsonify({'message' : 'This endpoint is not allowed!'})

    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'], method='sha256')
    new_org = Organization(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pw, admin=False)
    db.session.add(new_org)
    db.session.commit()
    return jsonify({"message": "New Organization Created!"})


@app.route('/organization/<public_id>', methods=["DELETE"])
@token_required 
def delete_organization(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'This endpoint is not allowed!'})

    qs = Organization.query.filter_by(public_id=public_id).first()

    if not qs:
        return jsonify({"message": "No Organization Found."})

    db.session.delete(qs)
    db.session.commit()

    return jsonify({"message": "This organization has been deleted."})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    qs = Organization.query.filter_by(name=auth.username).first()
    if not qs:
        return jsonify({"message": "No Organization Found."})

    if check_password_hash(qs.password, auth.password):
        token = jwt.encode({'public_id': qs.public_id, 
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                    app.config['SECRET_KEY'])
       
        return jsonify({'token': token.decode('utf-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


# ======================= Device Endpoints below ========================

@app.route('/devices', methods=['GET'])
@token_required
def get_all_devices(current_user):
    qs = Device.query.filter_by(organization_id=current_user.id).all()

    output = []
    for org in qs:
        org_data = {}
        org_data['id'] = org.id
        org_data['name'] = todo.text
        output.append(org_data)

    return jsonify({'organizations' : output})


@app.route('/devices/<device_id>', methods=['GET'])
@token_required
def get_device(current_user, device_id):
    qs = Device.query.filter_by(id=device_id, organization_id=current_user.id).first()

    if not todo:
        return jsonify({'message' : 'No device found!'})

    org_data = {}
    org_data['id'] = org.id
    org_data['name'] = todo.text

    return jsonify({'organizations' : output})


if __name__ == '__main__':
    app.run(debug=True, port=8080)

