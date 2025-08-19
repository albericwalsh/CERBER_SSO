# passenger_wsgi.py
import importlib
import sys
from a2wsgi import ASGIMiddleware

APP_MODULE = "app.main"  # chemin vers ton module FastAPI

def load_app():
    """
    Charge dynamiquement le module FastAPI et retourne l'application ASGI compatible WSGI.
    """
    try:
        if APP_MODULE in sys.modules:
            # Si le module est déjà importé, on le recharge pour prendre en compte les changements
            importlib.reload(sys.modules[APP_MODULE])
        module = importlib.import_module(APP_MODULE)

        # On récupère l'objet FastAPI depuis le module
        return ASGIMiddleware(module.app)
    except ImportError as e:
        print(f"Erreur lors du chargement du module {APP_MODULE}: {e}")
        sys.exit(1)

# Variable globale que Passenger va utiliser comme entry point
application = load_app()
