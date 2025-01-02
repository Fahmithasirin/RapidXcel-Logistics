import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'rapidxcel@2025')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///example.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
