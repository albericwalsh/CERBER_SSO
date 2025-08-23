import os


def get_public_path():
    root_dir = os.path.dirname(os.path.abspath(__file__))  # dossier app/
    public_path = os.path.join(root_dir, "../public")
    public_path = os.path.abspath(public_path)
    if not os.path.isdir(public_path):
        raise FileNotFoundError(f"Le répertoire public est introuvable : {public_path}")
    return public_path