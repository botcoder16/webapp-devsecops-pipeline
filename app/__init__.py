# app/__init__.py
from flask import Flask
import os

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24) # Generate a random key
    from .routes import main_bp
    app.register_blueprint(main_bp)
    return app
