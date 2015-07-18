#-*- coding:utf-8 -*-
import time
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash
from werkzeug.security import check_password_hash, generate_password_hash
from models import *

PER_PAGE = 10

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tuimimi.db'
app.debug = True
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = User.query.filter_by(username=username).first_or_404()
    return rv.user_id if rv else None

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')

def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.filter_by(user_id=session['user_id']).first_or_404()
    else:
        app.logger.warning('user_id not in session')

@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    message = Message.query.filter_by(author_id=session['user_id']).order_by('pub_date desc').limit(PER_PAGE)
    return render_template('timeline.html', messages=message)

@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    message = Message.query.order_by('pub_date desc').limit(PER_PAGE)
    return render_template('timeline.html', messages=message)

@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = User.query.filter_by(username=username).first_or_404()
    print profile_user
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = Follower.query.filter_by(who_id=session['user_id'],whom_id=profile_user.user_id).first() is not None
    message = Message.query.filter_by(author_id=profile_user.user_id).order_by('pub_date desc').limit(PER_PAGE)
    return render_template('timeline.html', messages=message,profile_user=profile_user,followed=followed)

@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    follower = Follower(session['user_id'], whom_id)
    db.session.add(follower)
    db.session.commit()
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))

@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    follower = Follower.query.filter_by(who_id=session['user_id'], whom_id=whom_id).first()
    db.session.delete(follower)
    db.session.commit()
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))

@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        message = Message(session['user_id'], request.form['text'], int(time.time()))
        db.session.add(message)
        db.session.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first_or_404()
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash( user.pw_hash, request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user.user_id
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif User.query.filter_by(username=request.form['username']).first() is not None:
            error = 'The username is already taken'
        else:
            user = User(request.form['username'], request.form['email'],
                        generate_password_hash(request.form['password']))
            print request.form['username'], request.form['email']
            db.session.add(user)
            db.session.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == '__main__':
    db.create_all()
    app.run()
