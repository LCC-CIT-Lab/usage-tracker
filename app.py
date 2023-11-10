from app import create_app
from app.models import db

import atexit

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # This will now be aware of the Flask app context
    app.run()
