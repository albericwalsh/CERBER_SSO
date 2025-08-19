# passenger_wsgi.py
import importlib
import sys
import traceback
from a2wsgi import ASGIMiddleware

APP_MODULE = "app.main"  # chemin vers ton module FastAPI

def load_app():
    """
    Charge dynamiquement le module FastAPI et retourne l'application ASGI compatible WSGI.
    Affiche les erreurs si le module ne peut pas être chargé.
    """
    try:
        if APP_MODULE in sys.modules:
            # Si le module est déjà importé, on le recharge pour prendre en compte les changements
            importlib.reload(sys.modules[APP_MODULE])
        module = importlib.import_module(APP_MODULE)

        # Activer le debug sur l'app FastAPI si possible
        if hasattr(module, "app"):
            module.app.debug = True

        return ASGIMiddleware(module.app)
    except Exception as e:
        # Affiche l'erreur complète dans la console Passenger
        traceback.print_exc()
        # Retourne une application WSGI minimale qui affiche l'erreur dans le navigateur
        def error_app(environ, start_response):
            start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
            return [str(e).encode("utf-8")]
        return error_app

# Variable globale que Passenger va utiliser comme entry point
application = load_app()
