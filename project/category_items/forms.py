from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms import TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from wtforms.validators import ValidationError
from category_items.models import User, Category, Item


# register form, validators and validate user, email
class RegistrationForm(FlaskForm):
    username = StringField(
                            'Username',
                            validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
                                    'Confirm Password',
                                    validators=[
                                        DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                                'That username is taken.'
                                'Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                                'That email is taken.'
                                'Please choose a different one.')


# login form and validators
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# category form and validators
class CategoryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Create')

    def validate_name(self, name):
        category = Category.query.filter_by(name=name.data).first()
        if category:
            raise ValidationError(
                                'That category is taken.'
                                'Please choose a different one.')


# item form and validators
class ItemForm(FlaskForm):
    categories = Category.query.all()
    cat_tuple = tuple()
    cat_array = []
    for category in categories:
        cat_tuple = (str(category.id), category.name)
        cat_array.append(cat_tuple)

    title = StringField('Title', validators=[DataRequired()])
    item_id = StringField('Item')
    description = TextAreaField('Description', validators=[DataRequired()])
    category = SelectField('Category', choices=cat_array)
    submit = SubmitField('Create')

    def validate_category(self, name):
        form = ItemForm()
        item = Item.query.filter_by(
                            cat_id=name.data).filter_by(
                                    title=form.title.data).filter(
                                        Item.id != form.item_id.data).first()
        if item:
            raise ValidationError(
                                'That item is taken within category.'
                                'Please choose a different one.')
