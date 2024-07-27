import re
from rich.console import Console

def extract_public_key(filename):
    console = Console()
    with open(filename, 'r') as file:
        key_data = file.read()

    pattern = re.compile(r'-----BEGIN PUBLIC KEY-----(.+)-----END PUBLIC KEY-----', re.DOTALL)
    match = pattern.search(key_data)
    if not match:
        raise console.ValueError("[bold red]La clé publique n'a pas été trouvée dans le fichier.[/bold red]")

    public_key_pem = match.group(1).strip()

    from base64 import b64decode
    public_key_der = b64decode(public_key_pem)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    public_key = serialization.load_der_public_key(public_key_der, default_backend())
    rsa_public_key = public_key.public_numbers()

    return rsa_public_key.n, rsa_public_key.e

