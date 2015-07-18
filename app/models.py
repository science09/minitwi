#-*- coding:utf-8 -*-
__author__ = '10124143'

from flask.ext.sqlalchemy import SQLAlchemy
from minitwi import app

db = SQLAlchemy(app)

class User(db.Model):
    user_id  = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email    = db.Column(db.String(30), unique=True, nullable=False)
    pw_hash  = db.Column(db.String(30), nullable=False)
    message = db.relationship('Message', backref='author', lazy='dynamic')

    def __init__(self, username, email, passwd):
        self.username = username
        self.email = email
        self.pw_hash = passwd

    def __repr__(self):
        return '<User %r>' % self.username

class Follower(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    who_id = db.Column(db.Integer)
    whom_id = db.Column(db.Integer)

    def __init__(self, who_id, whom_id):
        self.who_id = who_id
        self.whom_id = whom_id

    def __repr__(self):
        return '<Follower %d>' % self.who_id

class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.user_id'),nullable=False)
    text = db.Column(db.Text, nullable=False)
    pub_date = db.Column(db.Integer)

    def __init__(self, author_id, text, pub_date):
        self.author_id = author_id
        self.text = text
        self.pub_date = pub_date

    def __repr__(self):
        return '<Message %r>' % self.text