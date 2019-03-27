from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

app = Flask(__name__)
db = SQLAlchemy(app)


# class to create the table category
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    items = db.relationship('Item', backref='category_id', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'items': [i.serialize for i in self.items]
        }


# class to create the table item
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    cat_id = db.Column(
                        db.Integer,
                        db.ForeignKey('category.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'cat_id': self.cat_id,
            'user_id': self.user_id
        }


# class to create the table user
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    items = db.relationship(
                            'Item', backref='item_id',
                            lazy=True, uselist=False)
    categories = db.relationship('Category', backref='cat_id', lazy=True)

    @property
    def serialize(self):
        return {
            'email': self.email,
            'id': self.id,
            'categories': [i.serialize for i in self.categories]
        }
