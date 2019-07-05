from application import db


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