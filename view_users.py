from app import db
from app.models import User

def view_users():
    users = User.query.all()
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Role: {user.role}")

if __name__ == "__main__":
    view_users()
