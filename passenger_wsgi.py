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

        error_msg = "get public path"
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        error_msg = "La fonction get_public_path est introuvable dans le module app"
        # verifier le répertoire parent:
        from app.main import get_public_path
        public_path = get_public_path()
        if public_path is None:
            error_msg = "Impossible de déterminer le chemin du répertoire public."
            raise ImportError("Impossible de déterminer le chemin du répertoire public.")
        import os
        if not os.path.isdir(public_path):
            error_msg = ImportError(
                f"Le répertoire public est introuvable à l'emplacement : {public_path}\n"
                f"Contenu du parent ({os.path.dirname(public_path)}) : {os.listdir(os.path.dirname(public_path))}"
            ).__str__()
            raise ImportError(
                f"Le répertoire public est introuvable à l'emplacement : {public_path}\n"
                f"Contenu du parent ({os.path.dirname(public_path)}) : {os.listdir(os.path.dirname(public_path))}"
            )

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
