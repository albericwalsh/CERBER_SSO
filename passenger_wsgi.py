# passenger_wsgi.py
import os, sys
from dotenv import load_dotenv
from a2wsgi import ASGIMiddleware

# Ajoute le chemin de ton projet
sys.path.insert(0, os.path.dirname(__file__))

# Charge ton .env
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Import de ton app FastAPI
from app.main import app

# Conversion en WSGI pour Passenger
application = ASGIMiddleware(app)
