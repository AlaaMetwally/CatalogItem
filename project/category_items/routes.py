from flask import Flask, render_template, flash, redirect, url_for, request
from flask import abort, jsonify
from flask_bootstrap import Bootstrap
from category_items.forms import RegistrationForm, LoginForm, CategoryForm
from category_items.forms import ItemForm
from category_items.models import User, Category, Item
from category_items import app, db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import desc
from flask import session, json, make_response
from flask_oauth import OAuth

Bootstrap(app)

# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
ID = '378967825839-dto87c0v0r6q9t5ukakgh760ecujuq6m.apps.googleusercontent.com'
SECRET = 'j6ASZB4fdgio5S0AbZmdJAP8'
# one of the Redirect URIs from Google APIs console
REDIRECT_URI = '/authorized'
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
REQ_TOKEN = 'https://www.googleapis.com/auth/userinfo.email'
ACCESS_TOKEN = 'https://accounts.google.com/o/oauth2/token'
oauth = OAuth()

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url=AUTH_URL,
                          request_token_url=None,
                          request_token_params={'scope': REQ_TOKEN,
                                                'response_type': 'code'},
                          access_token_url=ACCESS_TOKEN,
                          access_token_method='POST',
                          access_token_params={
                                        'grant_type': 'authorization_code'},
                          consumer_key=ID,
                          consumer_secret=SECRET)


@app.route('/google_login')
def google_login():
    callback = url_for('authorized', _external=True)
    return google.authorize(callback=callback)


@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('google_login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)

        encoding = res.read().decode("utf-8")
        dic = json.loads(encoding)
        '''{ "id": "1234567",
        "email": "email@gmail.com",
        "verified_email": true,
        "picture":
        "https://lh5.googleusercontent.com/-cQgy-dvOEJQ/AAAAAAAAAAI/AAAAAAAAAAA/sxuKCxAiBr0/photo.jpg"
        }'''
        user = User.query.filter_by(email=dic["email"]).first()
        if user is None:
            hashed_password = bcrypt.generate_password_hash(
                                    '123456').decode('utf-8')
            new_user = User(
                    email=str(dic["email"]),
                    username=str(dic["email"].split("@")[0]),
                    password=hashed_password
                    )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
        else:
            login_user(user)
            categories = Category.query.filter_by(
                                user_id=user.id).order_by(
                                            desc(Category.date_category)).all()
            items = Item.query.filter_by(
                            user_id=user.id).order_by(
                                            desc(Item.date_item)).all()
            return render_template(
                'home.html', title='Home', category_exists='True',
                categories=categories, items=items)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('google_login'))
        return res.read()
    return redirect(url_for('home'))


@google.tokengetter
def get_access_token():
    return session.get('access_token')


# list of all categories JSON Endpoint
@app.route('/categories/JSON')
def categories_json():
    categories = Category.query.order_by(desc(Category.date_category)).all()
    return jsonify(categories=[i.serialize for i in categories])


# list of all items JSON Endpoint
@app.route('/items/JSON')
def items_json():
    items = Item.query.order_by(desc(Item.date_item)).all()
    return jsonify(items=[i.serialize for i in items])


# list of all users JSON Endpoint
@app.route('/users/JSON')
def users_json():
    users = User.query.all()
    return jsonify(users=[i.serialize for i in users])


# list of all items within certain category JSON Endpoint
@app.route(
    '/categories/<int:category_id>/item/<int:item_id>/JSON')
def categories_item_json(category_id, item_id):
    items = Item.query.filter_by(id=item_id, cat_id=category_id).all()
    return jsonify(items=[i.serialize for i in items])


# web page containing all categories and all items
@app.route('/')
@app.route("/home")
def home():
    categories = Category.query.order_by(
                                        desc(Category.date_category)).all()
    items = Item.query.order_by(desc(Item.date_item)).all()
    return render_template(
                        'home.html', title='Home', category_exists='True',
                        categories=categories, items=items)


# web page used for displaying register form and the process of creating user
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
                                form.password.data).decode('utf-8')
        user = User(
                username=form.username.data,
                email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        msg = 'Account created for ' + form.username.data + '!'
        flash(msg, 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


''' web page used for displaying login form
and the process of authenticating the user'''


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(
                    user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            home = redirect(url_for('home'))
            return redirect(next_page) if next_page else home
        else:
            flash(
                'Login Unsuccessful. Please check email and password',
                'danger')
    return render_template('login.html', title='Login', form=form)


# loging out from the project
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


# creating and storing new categories
@app.route("/category/new", methods=['GET', 'POST'])
@login_required
def new_category():
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data, user_id=current_user.id)
        db.session.add(category)
        db.session.commit()
        flash('Your category has been created!', 'success')
        return redirect(url_for('home'))
    return render_template(
            'create_category.html', title='New Category',
            form=form, legend='New Category')


# creating and storing new items
@app.route("/item/new", methods=['GET', 'POST'])
@login_required
def new_item():
    form = ItemForm()
    categories = Category.query.all()
    cat_dict = dict()
    cat_array = []
    for category in categories:
        cat_dict = {'id': str(category.id), 'name': category.name}
        cat_array.append(cat_dict)

    if form.validate_on_submit():
        item = Item(
                title=form.title.data, description=form.description.data,
                cat_id=form.category.data, user_id=current_user.id)
        db.session.add(item)
        db.session.commit()
        flash('Your item has been created!', 'success')
        return redirect(url_for('home'))
    return render_template(
                'create_item.html', title='New Item',
                form=form, legend='New Item', categories=cat_array)


# go to certain category and its details for each category has its own items
@app.route("/category/<int:category_id>")
def category(category_id):
    category = Category.query.get_or_404(category_id)
    categories = Category.query.order_by(desc(Category.date_category)).all()
    items = Item.query.order_by(
                                desc(Item.date_item)).filter_by(
                                cat_id=category_id).all()
    number_items = Item.query.order_by(
                                        desc(Item.date_item)).filter_by(
                                        cat_id=category_id).count()
    return render_template(
                        'home.html', title=category.name,
                        number_items=number_items,
                        categories=categories, items=items)


# go to certain item and its details
@app.route("/item/<int:item_id>")
def item(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item.html', title=item.title, item=item)


# displayiing edit page and edit certain item
@app.route("/item/<int:item_id>/update", methods=['GET', 'POST'])
@login_required
def update_item(item_id):
    categories = Category.query.all()
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        abort(403)
    form = ItemForm()
    if form.validate_on_submit():
        item.title = form.title.data
        item.description = form.description.data
        item.cat_id = form.category.data
        db.session.commit()
        flash('Your item has been updated!', 'success')
        return redirect(url_for('item', item_id=item.id))
    elif request.method == 'GET':
        form.title.data = item.title
        form.category.data = item.cat_id
        form.description.data = item.description
    return render_template(
                        'create_item.html', title='Update Item',
                        form=form, legend='Update Item',
                        item_id=item_id, categories=categories)


# delete certain item
@app.route("/item/<int:item_id>/delete", methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    flash('Your item has been deleted!', 'success')
    return redirect(url_for('home'))
