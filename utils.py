import os
import secrets

def save_file(file, upload_folder='static/uploads'):
    if not file or file.filename == '':
        return None
    ext = os.path.splitext(file.filename)[1]
    filename = secrets.token_hex(16) + ext
    folder = os.path.join(os.getcwd(), upload_folder)
    os.makedirs(folder, exist_ok=True)
    file.save(os.path.join(folder, filename))
    return filename