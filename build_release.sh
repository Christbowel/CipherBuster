#!/bin/bash
# Build CipherBuster v2.0 - Crée un exécutable standalone

echo "🔥 Build CipherBuster v2.0..."

# Installer PyInstaller
pip install pyinstaller

# Créer l'exécutable
pyinstaller \
    --onefile \
    --name "cipherbuster" \
    --add-data "lib:lib" \
    --hidden-import "gmpy2" \
    --hidden-import "sympy" \
    --hidden-import "rich" \
    --hidden-import "factordb" \
    --hidden-import "cryptography" \
    --hidden-import "Crypto" \
    cipherbuster.py

echo "✅ Binaire créé dans dist/cipherbuster"
echo "📦 Prêt pour GitHub Release!"