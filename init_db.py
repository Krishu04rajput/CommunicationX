"""Create/update the CommunicationX database schema."""
from app import app, db
import models  # noqa: F401

with app.app_context():
    db.create_all()
    print("CommunicationX database is ready.")
