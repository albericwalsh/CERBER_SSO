# passenger_wsgi.py - VERSION DEV
import importlib
import sys
import traceback
from a2wsgi import ASGIMiddleware

APP_MODULE = "app.main"  # chemin vers ton module FastAPI

# ⚡ Mode dev : affiche toutes les erreurs directement dans le navigateur
DEV_MODE = True

def load_app():
    error_msg : str = ""
    try:
        error_msg = "db connection"
        # Teste la connexion à la base de données avant de charger l'app
        from app.database import check_db_connection
        db_status = check_db_connection()
        if db_status != "ok":
            raise ImportError(f"Erreur de connexion à la base de données : {db_status}")

        error_msg = "Vérification du répertoire public"
        # Vérifie que le répertoire public existe
        from app.main import check_public_dir
        error_msg = check_public_dir()

        error_msg = "Importation du module principal"
        if APP_MODULE in sys.modules:
            importlib.reload(sys.modules[APP_MODULE])
        module = importlib.import_module(APP_MODULE)

        error_msg = "Vérification de l'environnement de l'application"
        if hasattr(module, "app"):
            module.app.debug = DEV_MODE  # Active le debug FastAPI si DEV_MODE

        error_msg = "Création du middleware ASGI"
        app = ASGIMiddleware(module.app)

        def dev_app(environ, start_response):
            try:
                return app(environ, start_response)
            except Exception as e:
                # Log complet côté serveur
                traceback.print_exc()
                # Affiche la stacktrace dans le navigateur
                tb = traceback.format_exc()
                start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
                return [f"Erreur dans l'application :\n\n{tb}\n\n{e}".encode("utf-8")]

        return dev_app

    except ImportError as e:
        print(f"Erreur d'importation du module {APP_MODULE}: {e}")
        traceback.print_exc()
        def error_app(environ, start_response):
            tb = traceback.format_exc()
            start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
            return [f"Impossible de charger l'application :\n\n{error_msg}\n\n{tb}".encode("utf-8")]
        return error_app

application = load_app()
