import os

import yaml

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
Base = db.Model


def load_db_config():
    with open('db_config.yaml', 'r') as file:
        config = yaml.safe_load(file)
    return config


def init_db(app):
    db_config = load_db_config()
    user = db_config['user']
    pwd = db_config['password']
    host = db_config['host']
    port = db_config['port']
    db_name = db_config['db']
    schema = db_config['schema']

    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{user}:{pwd}@{host}:{port}/{db_name}?options=-c%20search_path={schema}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
