"""Local authentication for CommunicationX.

Accounts are stored in the application's
SQLAlchemy database and authenticated with Flask-Login.
"""
from functools import wraps
from flask import redirect, url_for, session, request, flash
from flask_login import LoginManager, current_user
from app import app

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    from models import User
    try:
        return User.query.get(int(user_id))
    except (TypeError, ValueError):
        return None

def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            session["next_url"] = request.url
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped
