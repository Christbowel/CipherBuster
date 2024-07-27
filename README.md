# CipherBuster

CipherBuster est un framework professionnel dédié à l'exploitation des vulnérabilités dans le chiffrement RSA. Ce document décrit en détail les différentes attaques et fonctionnalités disponibles dans CipherBuster.

## Fonctionnalités

### 1) 🧩 Franklin-Reiter Attack
**Description :**  
Exploite une situation où deux messages chiffrés avec la même clé publique ont une structure de message linéairement reliée. En utilisant cette relation, l'attaque permet de retrouver les messages originaux.

**Utilisation :**  
Permet de démontrer les risques d'utiliser des messages liés avec la même clé publique.

### 2) 🔑 Common Modulus Attack
**Description :**  
Cette attaque est utilisée lorsque deux messages sont chiffrés avec des exposants publics différents mais le même module. Elle permet de récupérer les messages originaux sans connaître la clé privée.

**Utilisation :**  
Idéale pour montrer la faiblesse des systèmes utilisant des modules communs avec des exposants différents.

### 3) 🧮 Simple Factorization Attack
**Description :**  
Cette attaque tente de factoriser le module RSA (produit de deux grands nombres premiers) en utilisant diverses techniques de factorisation. Une fois le module factorisé, il devient possible de calculer la clé privée.

**Utilisation :**  
Cruciale pour illustrer la sécurité basée sur la difficulté de factorisation des grands nombres.

### 4) 🔍 Wiener's Attack
**Description :**  
L'attaque de Wiener cible les clés privées faibles, en particulier lorsque l'exposant privé est petit. En analysant les fractions continues de l'exposant public sur le module, cette attaque peut récupérer la clé privée.

**Utilisation :**  
Démontre les dangers d'utiliser des clés privées trop petites.

### 5) 🔐 Simple RSA Encoding and Decoding
**Description :**  
Permet de chiffrer et déchiffrer des messages en utilisant l'algorithme RSA standard. Utile pour tester et comprendre le fonctionnement de base de RSA.

**Utilisation :**  
Utile pour l'éducation et la vérification des implémentations RSA.

### 6) 🌀 Pollard's Rho Attack
**Description :**  
Pollard's Rho est une méthode probabiliste pour factoriser de grands nombres, particulièrement efficace pour les nombres ayant des facteurs de taille similaire. Utilisé pour casser le module RSA en facteurs premiers.

**Utilisation :**  
Montre l'efficacité des méthodes probabilistes dans la factorisation de nombres RSA.

### 7) 📋 Public Key Parameters Extraction
**Description :**  
Extrait les paramètres clés (n, e) de la clé publique RSA, nécessaires pour effectuer diverses attaques et pour chiffrer/déchiffrer des messages.

**Utilisation :**  
Essentiel pour préparer les paramètres nécessaires à d'autres attaques RSA.

### 8) 🔗 Common Prime Factor Attack
**Description :**  
Lorsqu'un même nombre premier est utilisé dans la génération de plusieurs modules RSA, cette attaque permet de factoriser ces modules et de récupérer les clés privées associées.

**Utilisation :**  
Met en évidence le risque de réutiliser des nombres premiers dans plusieurs clés RSA.

### 9) 🗝 Private Key Computation
**Description :**  
Une fois les facteurs premiers d'un module RSA obtenus, cette fonctionnalité calcule la clé privée correspondante, permettant ainsi le déchiffrement des messages chiffrés avec cette clé publique.

**Utilisation :**  
Finalise le processus d'attaque en calculant la clé privée pour déchiffrer les données.

### 0) 🚪 Exit
**Description :**  
Option pour quitter le framework.


# UTILISATION

```bash

 ______      __           ___           __
 / ___(_)__  / /  ___ ____/ _ )__ _____ / /____ ____
/ /__/ / _ \/ _ \/ -_) __/ _  / // (_-</ __/ -_) __/
\___/_/ .__/_//_/\__/_/ /____/\_,_/___/\__/\__/_/    v1.0
     /_/
    Creator: Christbowel

    
This framework is a tool dedicated to exploiting vulnerabilities in RSA encryption.


    1) Franklin-Reiter Attack
    2) Common Modulus Attack
    3) Simple Factorization Attack
    4) Wiener's Attack
    5) Simple RSA Encoding and Decoding
    6) Pollard's Rho Attack
    7) Public Key Parameters Extraction
    8) Common Prime Factor Attack
    9) Private Key Computation
    0) Exit
    

```

Entrer juste un numero et tout se fera automatiquement en fonction des paramètres passés.
