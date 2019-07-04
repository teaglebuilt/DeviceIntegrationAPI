from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid


app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/dillanteagle/workspace/coach_logic_API/api.db'

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


@app.route('/organizations', methods=['GET'])
def get_all_organizations():
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
def get_one_organization(public_id):
    qs = Organization.query.filter_by(public_id=public_id).first()
    if not qs:
        return jsonify({"message": "No Organization Found."})

    org_data = {}
    org_data['public_id'] = org.public_id
    org_data['name'] = org.name
    org_data['password'] = org.password
    org_data['admin'] = org.admin
    return jsonify({"organization": org_data})
    

@app.route('/organization', methods=['POST'])
def create_organization():
    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'], method='sha256')
    new_org = Organization(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_pw, admin=False)
    db.session.add(new_org)
    db.session.commit()
    return jsonify({"message": "New Organization Created!"})

@app.route('/organization/<public_id>', methods=["DELETE"])
def delete_organization(public_id):
    qs = Organization.query.filter_by(public_id=public_id).first()

    if not qs:
        return jsonify({"message": "No Organization Found."})

    db.session.delete(qs)
    db.session.commit()

    return jsonify({"message": "This organization has been deleted."})


if __name__ == '__main__':
    app.run(debug=True, port=8080)

