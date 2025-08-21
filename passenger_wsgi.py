# passenger_wsgi.py - VERSION PRODUCTION
import importlib
import sys
import traceback
from a2wsgi import ASGIMiddleware

APP_MODULE = "app.main"  # chemin vers ton module FastAPI


def load_app():
    try:
        if APP_MODULE in sys.modules:
            importlib.reload(sys.modules[APP_MODULE])
        module = importlib.import_module(APP_MODULE)

        if hasattr(module, "app"):
            module.app.debug = False  # ⚠️ Désactiver le mode debug

        app = ASGIMiddleware(module.app)

        # Middleware WSGI qui loggue mais ne montre pas les erreurs aux clients
        def production_app(environ, start_response):
            try:
                return app(environ, start_response)
            except Exception:
                traceback.print_exc()  # log complet côté serveur
                start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
                return [b"Une erreur interne est survenue."]

        return production_app

    except Exception:
        traceback.print_exc()

        def error_app(environ, start_response):
            start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
            return [b"Impossible de charger l'application."]
        return error_app


application = load_app()
