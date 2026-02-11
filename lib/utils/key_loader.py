"""
Key Loader Universel - Supporte TOUS les formats de clés RSA
Formats supportés:
- PEM (-----BEGIN PUBLIC/PRIVATE KEY-----)
- DER (binaire)
- OpenSSH (ssh-rsa AAAA...)
- PGP/GPG (-----BEGIN PGP PUBLIC KEY BLOCK-----)
- XML RSA (Microsoft format)
- JSON Web Key (JWK)
- Raw n,e / n,d (hex ou decimal)
- Certificats X.509 (.crt, .cer, .pem)
- PKCS#12 (.pfx, .p12) avec mot de passe
"""

import base64
import struct
import json
import re
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass


@dataclass
class RSAKeyData:
    """Données complètes d'une clé RSA"""
    # Paramètres publics
    n: Optional[int] = None
    e: Optional[int] = None
    # Paramètres privés
    d: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None
    dp: Optional[int] = None
    dq: Optional[int] = None
    qinv: Optional[int] = None
    # Métadonnées
    key_type: str = "unknown"
    key_size: int = 0
    format_detected: str = "unknown"
    is_private: bool = False
    is_public: bool = False


class UniversalKeyLoader:
    """
    Charge des clés RSA depuis n'importe quel format
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
    
    def load(self, source: str, password: str = None) -> RSAKeyData:
        """
        Charge une clé depuis un fichier ou une string
        
        Args:
            source: Chemin du fichier OU string contenant la clé
            password: Mot de passe pour clés PKCS#12 ou chiffrées
            
        Returns:
            RSAKeyData avec les paramètres extraits
        """
        # Détecter si c'est un fichier ou une string
        import os
        
        if os.path.isfile(source):
            self._log(f"Chargement du fichier: {source}")
            return self._load_from_file(source, password)
        else:
            self._log("Chargement depuis string directe")
            return self._load_from_string(source, password)
    
    def _load_from_file(self, filepath: str, password: str = None) -> RSAKeyData:
        """Charge depuis un fichier"""
        import os
        
        ext = os.path.splitext(filepath)[1].lower()
        
        # Détecter le format selon l'extension
        binary_formats = ['.der', '.pfx', '.p12', '.cer']
        
        if ext in binary_formats:
            with open(filepath, 'rb') as f:
                data = f.read()
            return self._load_binary(data, ext, password)
        else:
            # Format texte
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            return self._load_from_string(content, password)
    
    def _load_from_string(self, content: str, password: str = None) -> RSAKeyData:
        """Détecte et charge le format depuis une string"""
        content = content.strip()
        
        # Liste des détecteurs dans l'ordre de priorité
        detectors = [
            ("PEM Public Key", self._detect_pem_public, self._load_pem_public),
            ("PEM Private Key", self._detect_pem_private, self._load_pem_private),
            ("PEM Certificate", self._detect_pem_cert, self._load_pem_cert),
            ("PEM Encrypted", self._detect_pem_encrypted, self._load_pem_encrypted),
            ("OpenSSH Public", self._detect_openssh, self._load_openssh),
            ("JWK JSON", self._detect_jwk, self._load_jwk),
            ("XML RSA", self._detect_xml, self._load_xml),
            ("Hex n,e", self._detect_raw_hex, self._load_raw_hex),
            ("PGP Block", self._detect_pgp, self._load_pgp),
        ]
        
        for format_name, detector, loader in detectors:
            if detector(content):
                self._log(f"Format détecté: {format_name}")
                try:
                    result = loader(content, password)
                    result.format_detected = format_name
                    return result
                except Exception as e:
                    self._log(f"Échec chargement {format_name}: {e}", "WARNING")
                    continue
        
        # Dernier recours: essayer d'extraire n,e depuis texte brut
        return self._extract_raw_numbers(content)
    
    # === DÉTECTEURS ===
    
    def _detect_pem_public(self, content: str) -> bool:
        return any(header in content for header in [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----"
        ])
    
    def _detect_pem_private(self, content: str) -> bool:
        return any(header in content for header in [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----"
        ])
    
    def _detect_pem_cert(self, content: str) -> bool:
        return "-----BEGIN CERTIFICATE-----" in content
    
    def _detect_pem_encrypted(self, content: str) -> bool:
        return "-----BEGIN ENCRYPTED PRIVATE KEY-----" in content
    
    def _detect_openssh(self, content: str) -> bool:
        return content.startswith("ssh-rsa ") or "-----BEGIN OPENSSH PRIVATE KEY-----" in content
    
    def _detect_jwk(self, content: str) -> bool:
        try:
            data = json.loads(content)
            return "kty" in data or "n" in data
        except:
            return False
    
    def _detect_xml(self, content: str) -> bool:
        return "<RSAKeyValue>" in content or "<RSAParameters>" in content
    
    def _detect_raw_hex(self, content: str) -> bool:
        patterns = [
            r'n\s*[=:]\s*0x[0-9a-fA-F]+',
            r'n\s*[=:]\s*[0-9]{4,}',
            r'modulus\s*[=:]\s*[0-9a-fA-F]+',
            r'Modulus\s*[=:]\s*[0-9]+',
            r'e\s*[=:]\s*[0-9]+',
            r'Exponent\s*[=:]\s*[0-9]+',
        ]
        return any(re.search(p, content, re.IGNORECASE) for p in patterns)
    
    def _detect_pgp(self, content: str) -> bool:
        return "-----BEGIN PGP PUBLIC KEY BLOCK-----" in content
    
    # === LOADERS ===
    
    def _load_pem_public(self, content: str, password=None) -> RSAKeyData:
        """Charge une clé publique PEM"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        key_data = RSAKeyData()
        
        try:
            # Essai 1: Format SPKI standard
            public_key = serialization.load_pem_public_key(
                content.encode(),
                backend=default_backend()
            )
            
            pub_numbers = public_key.public_key().public_numbers() \
                if hasattr(public_key, 'public_key') else public_key.public_numbers()
            
            key_data.n = pub_numbers.n
            key_data.e = pub_numbers.e
            key_data.key_size = public_key.key_size if hasattr(public_key, 'key_size') else pub_numbers.n.bit_length()
            key_data.is_public = True
            key_data.key_type = "RSA Public Key"
            
            self._log(f"✓ Clé publique PEM chargée: {key_data.key_size} bits")
            return key_data
            
        except Exception as e1:
            # Essai 2: Format PKCS#1
            try:
                # Extraire base64 et parser ASN.1 manuellement
                b64_content = re.sub(r'-----[^-]+-----', '', content).strip()
                der_data = base64.b64decode(b64_content)
                
                n, e = self._parse_pkcs1_public_der(der_data)
                key_data.n = n
                key_data.e = e
                key_data.key_size = n.bit_length()
                key_data.is_public = True
                key_data.key_type = "RSA Public Key (PKCS#1)"
                
                self._log(f"✓ Clé publique PKCS#1 chargée: {key_data.key_size} bits")
                return key_data
                
            except Exception as e2:
                raise ValueError(f"Impossible de charger la clé publique PEM: {e1}, {e2}")
    
    def _load_pem_private(self, content: str, password=None) -> RSAKeyData:
        """Charge une clé privée PEM"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        key_data = RSAKeyData()
        
        pwd = password.encode() if isinstance(password, str) else password
        
        try:
            private_key = serialization.load_pem_private_key(
                content.encode(),
                password=pwd,
                backend=default_backend()
            )
            
            priv_numbers = private_key.private_numbers()
            pub_numbers = priv_numbers.public_numbers
            
            key_data.n = pub_numbers.n
            key_data.e = pub_numbers.e
            key_data.d = priv_numbers.d
            key_data.p = priv_numbers.p
            key_data.q = priv_numbers.q
            key_data.dp = priv_numbers.dmp1
            key_data.dq = priv_numbers.dmq1
            key_data.qinv = priv_numbers.iqmp
            key_data.key_size = private_key.key_size
            key_data.is_private = True
            key_data.is_public = True
            key_data.key_type = "RSA Private Key"
            
            self._log(f"✓ Clé privée PEM chargée: {key_data.key_size} bits")
            return key_data
            
        except Exception as e:
            raise ValueError(f"Impossible de charger la clé privée PEM: {e}")
    
    def _load_pem_cert(self, content: str, password=None) -> RSAKeyData:
        """Charge depuis certificat X.509"""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        key_data = RSAKeyData()
        
        try:
            cert = x509.load_pem_x509_certificate(content.encode(), default_backend())
            public_key = cert.public_key()
            pub_numbers = public_key.public_numbers()
            
            key_data.n = pub_numbers.n
            key_data.e = pub_numbers.e
            key_data.key_size = public_key.key_size
            key_data.is_public = True
            key_data.key_type = "X.509 Certificate"
            
            # Informations du certificat
            try:
                subject = cert.subject.rfc4514_string()
                key_data.format_detected = f"X.509 ({subject[:50]})"
            except:
                pass
            
            self._log(f"✓ Certificat X.509 chargé: {key_data.key_size} bits")
            return key_data
            
        except Exception as e:
            raise ValueError(f"Impossible de charger le certificat: {e}")
    
    def _load_pem_encrypted(self, content: str, password=None) -> RSAKeyData:
        """Charge une clé privée chiffrée"""
        if not password:
            from rich.prompt import Prompt
            password = Prompt.ask("🔑 Mot de passe pour la clé chiffrée", password=True)
        
        return self._load_pem_private(content, password)
    
    def _load_openssh(self, content: str, password=None) -> RSAKeyData:
        """Charge une clé OpenSSH publique"""
        key_data = RSAKeyData()
        
        content = content.strip()
        
        # Clé publique OpenSSH: "ssh-rsa AAAA... comment"
        if content.startswith("ssh-rsa "):
            parts = content.split()
            if len(parts) >= 2:
                key_b64 = parts[1]
                key_bytes = base64.b64decode(key_b64)
                
                # Parser le format OpenSSH
                n, e = self._parse_openssh_public(key_bytes)
                
                key_data.n = n
                key_data.e = e
                key_data.key_size = n.bit_length()
                key_data.is_public = True
                key_data.key_type = "OpenSSH Public Key"
                
                if len(parts) >= 3:
                    key_data.format_detected = f"OpenSSH (comment: {parts[2][:30]})"
                
                self._log(f"✓ Clé OpenSSH publique chargée: {key_data.key_size} bits")
                return key_data
        
        # Clé privée OpenSSH
        elif "-----BEGIN OPENSSH PRIVATE KEY-----" in content:
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.backends import default_backend
                
                pwd = password.encode() if isinstance(password, str) else password
                
                private_key = serialization.load_ssh_private_key(
                    content.encode(),
                    password=pwd,
                    backend=default_backend()
                )
                
                priv_numbers = private_key.private_numbers()
                pub_numbers = priv_numbers.public_numbers
                
                key_data.n = pub_numbers.n
                key_data.e = pub_numbers.e
                key_data.d = priv_numbers.d
                key_data.p = priv_numbers.p
                key_data.q = priv_numbers.q
                key_data.key_size = private_key.key_size
                key_data.is_private = True
                key_data.is_public = True
                key_data.key_type = "OpenSSH Private Key"
                
                self._log(f"✓ Clé privée OpenSSH chargée: {key_data.key_size} bits")
                return key_data
            except Exception as e:
                raise ValueError(f"Erreur OpenSSH privée: {e}")
        
        raise ValueError("Format OpenSSH non reconnu")
    
    def _load_jwk(self, content: str, password=None) -> RSAKeyData:
        """Charge depuis JSON Web Key (JWK)"""
        key_data = RSAKeyData()
        
        data = json.loads(content)
        
        def b64url_decode(s):
            """Décoder base64url en entier"""
            s += '=' * (4 - len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(s), 'big')
        
        # Vérifier que c'est RSA
        kty = data.get("kty", "")
        if kty and kty != "RSA":
            raise ValueError(f"Ce n'est pas une clé RSA (kty={kty})")
        
        # Paramètres publics
        if "n" in data:
            key_data.n = b64url_decode(data["n"])
        if "e" in data:
            key_data.e = b64url_decode(data["e"])
        
        # Paramètres privés
        if "d" in data:
            key_data.d = b64url_decode(data["d"])
            key_data.is_private = True
        if "p" in data:
            key_data.p = b64url_decode(data["p"])
        if "q" in data:
            key_data.q = b64url_decode(data["q"])
        if "dp" in data:
            key_data.dp = b64url_decode(data["dp"])
        if "dq" in data:
            key_data.dq = b64url_decode(data["dq"])
        if "qi" in data:
            key_data.qinv = b64url_decode(data["qi"])
        
        key_data.is_public = key_data.n is not None
        key_data.key_size = key_data.n.bit_length() if key_data.n else 0
        key_data.key_type = "JWK RSA"
        
        self._log(f"✓ JWK chargée: {key_data.key_size} bits")
        return key_data
    
    def _load_xml(self, content: str, password=None) -> RSAKeyData:
        """Charge depuis format XML RSA (Microsoft)"""
        import xml.etree.ElementTree as ET
        
        key_data = RSAKeyData()
        
        def b64_to_int(s):
            """Décoder base64 en entier"""
            return int.from_bytes(base64.b64decode(s), 'big')
        
        # Essayer de parser le XML
        # Supprimer les namespaces si présents
        clean_content = re.sub(r' xmlns[^"]*"[^"]*"', '', content)
        
        try:
            root = ET.fromstring(clean_content)
        except ET.ParseError:
            # Essayer d'extraire les balises directement
            root = ET.fromstring(f"<root>{clean_content}</root>")
        
        # Mapper les balises XML aux paramètres RSA
        mappings = {
            "Modulus": "n",
            "Exponent": "e",
            "D": "d",
            "P": "p",
            "Q": "q",
            "DP": "dp",
            "DQ": "dq",
            "InverseQ": "qinv"
        }
        
        for xml_name, param_name in mappings.items():
            # Chercher la balise (case insensitive)
            for tag in [xml_name, xml_name.lower(), xml_name.upper()]:
                elem = root.find(f".//{tag}")
                if elem is not None and elem.text:
                    try:
                        setattr(key_data, param_name, b64_to_int(elem.text.strip()))
                        break
                    except:
                        pass
        
        if key_data.n is None:
            raise ValueError("Aucun paramètre n trouvé dans le XML")
        
        key_data.is_public = True
        key_data.is_private = key_data.d is not None
        key_data.key_size = key_data.n.bit_length()
        key_data.key_type = "XML RSA"
        
        self._log(f"✓ Clé XML chargée: {key_data.key_size} bits")
        return key_data
    
    def _load_raw_hex(self, content: str, password=None) -> RSAKeyData:
        """Charge depuis format brut n, e en hex ou décimal"""
        key_data = RSAKeyData()
    
        # Patterns pour n
        patterns_n = [
            r'n\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'n\s*[=:]\s*([0-9]{4,})',
            r'modulus\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'modulus\s*[=:]\s*([0-9]{4,})',
            r'Modulus\s*[=:]\s*([0-9]{4,})',
        ]
    
        # Patterns pour e
        patterns_e = [
            r'e\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'e\s*[=:]\s*([0-9]+)',
            r'exponent\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'exponent\s*[=:]\s*([0-9]+)',
            r'Exponent\s*[=:]\s*([0-9]+)',
            r'E\s*[=:]\s*([0-9]+)',
        ]
    
        # Patterns pour d
        patterns_d = [
            r'\bd\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'\bd\s*[=:]\s*([0-9]{4,})',
        ]
    
        def extract_int(patterns_list, text):
            for pattern in patterns_list:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    val = match.group(1).strip()
                    try:
                        return int(val, 16) if val.startswith('0x') else int(val)
                    except:
                        continue
            return None
    
        key_data.n = extract_int(patterns_n, content)
        key_data.e = extract_int(patterns_e, content)
        key_data.d = extract_int(patterns_d, content)
    
        if key_data.n is None:
            raise ValueError("Impossible d'extraire n du texte")
    
        key_data.is_public = True
        key_data.is_private = key_data.d is not None
        key_data.key_size = key_data.n.bit_length()
        key_data.key_type = "Raw Parameters"
        key_data.format_detected = "Raw text extraction"
    
        self._log(f"✓ Paramètres extraits: n={key_data.key_size} bits")
        return key_data
    
    def _load_pgp(self, content: str, password=None) -> RSAKeyData:
        """Charge depuis bloc PGP"""
        key_data = RSAKeyData()
        
        try:
            # Extraire le contenu base64 du bloc PGP
            lines = content.split('\n')
            b64_lines = []
            in_block = False
            
            for line in lines:
                if line.startswith('-----BEGIN PGP'):
                    in_block = True
                    continue
                elif line.startswith('-----END PGP'):
                    break
                elif in_block and line and not line.startswith('=') and ': ' not in line:
                    b64_lines.append(line.strip())
            
            pgp_data = base64.b64decode(''.join(b64_lines))
            
            # Parser le paquet OpenPGP (format simplifié)
            n, e = self._parse_pgp_public_key(pgp_data)
            
            key_data.n = n
            key_data.e = e
            key_data.key_size = n.bit_length()
            key_data.is_public = True
            key_data.key_type = "PGP Public Key"
            
            self._log(f"✓ Clé PGP chargée: {key_data.key_size} bits")
            return key_data
            
        except Exception as e:
            raise ValueError(f"Erreur PGP: {e}")
    
    def _load_binary(self, data: bytes, ext: str, password=None) -> RSAKeyData:
        """Charge depuis format binaire (DER, PKCS#12)"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        key_data = RSAKeyData()
        
        if ext == '.der':
            # Essayer public key DER
            try:
                public_key = serialization.load_der_public_key(data, default_backend())
                pub_numbers = public_key.public_numbers()
                key_data.n = pub_numbers.n
                key_data.e = pub_numbers.e
                key_data.key_size = public_key.key_size
                key_data.is_public = True
                key_data.key_type = "DER Public Key"
                self._log(f"✓ DER public key: {key_data.key_size} bits")
                return key_data
            except:
                pass
            
            # Essayer private key DER
            try:
                pwd = password.encode() if isinstance(password, str) else password
                private_key = serialization.load_der_private_key(data, password=pwd, backend=default_backend())
                priv_numbers = private_key.private_numbers()
                pub_numbers = priv_numbers.public_numbers
                key_data.n = pub_numbers.n
                key_data.e = pub_numbers.e
                key_data.d = priv_numbers.d
                key_data.p = priv_numbers.p
                key_data.q = priv_numbers.q
                key_data.key_size = private_key.key_size
                key_data.is_private = True
                key_data.is_public = True
                key_data.key_type = "DER Private Key"
                self._log(f"✓ DER private key: {key_data.key_size} bits")
                return key_data
            except Exception as e:
                raise ValueError(f"Impossible de charger le DER: {e}")
        
        elif ext in ['.pfx', '.p12']:
            # PKCS#12
            from cryptography.hazmat.primitives.serialization import pkcs12
            
            if not password:
                from rich.prompt import Prompt
                password = Prompt.ask("🔑 Mot de passe PKCS#12", password=True)
            
            pwd = password.encode() if isinstance(password, str) else password
            
            try:
                private_key, cert, chain = pkcs12.load_key_and_certificates(
                    data, pwd, default_backend()
                )
                
                if private_key:
                    priv_numbers = private_key.private_numbers()
                    pub_numbers = priv_numbers.public_numbers
                    key_data.n = pub_numbers.n
                    key_data.e = pub_numbers.e
                    key_data.d = priv_numbers.d
                    key_data.p = priv_numbers.p
                    key_data.q = priv_numbers.q
                    key_data.key_size = private_key.key_size
                    key_data.is_private = True
                    key_data.is_public = True
                    key_data.key_type = "PKCS#12"
                
                self._log(f"✓ PKCS#12 chargé: {key_data.key_size} bits")
                return key_data
                
            except Exception as e:
                raise ValueError(f"Erreur PKCS#12 (mot de passe incorrect?): {e}")
        
        raise ValueError(f"Format binaire {ext} non supporté")
    
    # === HELPERS ASN.1 ===
    
    def _parse_pkcs1_public_der(self, data: bytes) -> Tuple[int, int]:
        """Parse manuellement une clé publique PKCS#1 en DER"""
        def read_length(data, pos):
            if data[pos] < 0x80:
                return data[pos], pos + 1
            num_bytes = data[pos] & 0x7f
            length = int.from_bytes(data[pos+1:pos+1+num_bytes], 'big')
            return length, pos + 1 + num_bytes
        
        def read_integer(data, pos):
            assert data[pos] == 0x02, f"Expected INTEGER, got {hex(data[pos])}"
            length, pos = read_length(data, pos + 1)
            value = int.from_bytes(data[pos:pos+length], 'big')
            return value, pos + length
        
        pos = 0
        # SEQUENCE
        assert data[pos] == 0x30
        _, pos = read_length(data, pos + 1)
        
        # N
        n, pos = read_integer(data, pos)
        
        # E
        e, pos = read_integer(data, pos)
        
        return n, e
    
    def _parse_openssh_public(self, data: bytes) -> Tuple[int, int]:
        """Parse une clé publique OpenSSH"""
        pos = 0
        
        def read_mpint(data, pos):
            length = struct.unpack('>I', data[pos:pos+4])[0]
            value = int.from_bytes(data[pos+4:pos+4+length], 'big')
            return value, pos + 4 + length
        
        def read_string(data, pos):
            length = struct.unpack('>I', data[pos:pos+4])[0]
            value = data[pos+4:pos+4+length]
            return value, pos + 4 + length
        
        # Lire le type de clé
        key_type, pos = read_string(data, pos)
        
        if key_type != b'ssh-rsa':
            raise ValueError(f"Type de clé non supporté: {key_type}")
        
        # Lire e et n (ordre OpenSSH: e, n)
        e, pos = read_mpint(data, pos)
        n, pos = read_mpint(data, pos)
        
        return n, e
    
    def _parse_pgp_public_key(self, data: bytes) -> Tuple[int, int]:
        """Parse basique d'un paquet PGP"""
        pos = 0
        
        # Paquet PGP (format simplifié)
        packet_tag = data[pos]
        pos += 1
        
        # Longueur du paquet
        if data[pos] < 192:
            length = data[pos]
            pos += 1
        elif data[pos] < 255:
            length = ((data[pos] - 192) << 8) + data[pos+1] + 192
            pos += 2
        else:
            pos += 1
            length = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
        
        # Version du paquet clé
        version = data[pos]
        pos += 1
        
        # Timestamp (4 bytes)
        pos += 4
        
        if version == 4:
            # Algorithme
            algo = data[pos]
            pos += 1
            
            if algo != 1:  # 1 = RSA
                raise ValueError(f"Algorithme PGP non RSA: {algo}")
            
            # Lire les MPI (Multi-Precision Integers)
            def read_mpi(data, pos):
                bits = struct.unpack('>H', data[pos:pos+2])[0]
                pos += 2
                byte_length = (bits + 7) // 8
                value = int.from_bytes(data[pos:pos+byte_length], 'big')
                return value, pos + byte_length
            
            n, pos = read_mpi(data, pos)
            e, pos = read_mpi(data, pos)
            
            return n, e
        
        raise ValueError(f"Version PGP {version} non supportée")
    
    def _extract_raw_numbers(self, content: str) -> RSAKeyData:
        """Dernier recours: extraire des nombres depuis texte libre"""
        key_data = RSAKeyData()
        
        # Chercher de grands nombres dans le texte
        numbers = re.findall(r'\b\d{20,}\b', content)
        hex_numbers = re.findall(r'0x[0-9a-fA-F]{40,}', content)
        
        all_nums = [int(n) for n in numbers]
        all_nums += [int(h, 16) for h in hex_numbers]
        
        # Le plus grand est probablement n
        if all_nums:
            all_nums.sort(reverse=True)
            key_data.n = all_nums[0]
            key_data.key_size = key_data.n.bit_length()
            key_data.is_public = True
            key_data.key_type = "Extracted from text"
            key_data.format_detected = "Raw text extraction"
            
            self._log(f"⚠ Extraction depuis texte brut: n={key_data.key_size} bits", "WARNING")
        else:
            raise ValueError("Aucun paramètre RSA trouvé")
        
        return key_data
    
    def display_key_info(self, key_data: RSAKeyData):
        """Affiche les informations de la clé de manière stylée"""
        from rich.console import Console
        from rich.table import Table
        from rich import box
        
        console = Console()
        
        table = Table(
            title=f"🔑 Informations de la Clé RSA",
            box=box.ROUNDED
        )
        table.add_column("Paramètre", style="cyan")
        table.add_column("Valeur", style="white")
        table.add_column("Status", style="green")
        
        table.add_row("Format", key_data.format_detected, "✓")
        table.add_row("Type", key_data.key_type, "✓")
        table.add_row("Taille", f"{key_data.key_size} bits", 
                     "✅ Fort" if key_data.key_size >= 2048 else "⚠️ Faible")
        table.add_row("Publique", "✓" if key_data.is_public else "✗", "")
        table.add_row("Privée", "✓" if key_data.is_private else "✗", "")
        
        if key_data.n:
            table.add_row("n (tronqué)", f"{str(key_data.n)[:40]}...", "✓")
        if key_data.e:
            table.add_row("e", str(key_data.e), 
                         "✅ Standard" if key_data.e == 65537 else "⚠️ Non-standard")
        if key_data.d:
            table.add_row("d", f"{str(key_data.d)[:30]}...", "✓ Privé")
        if key_data.p:
            table.add_row("p", f"{str(key_data.p)[:30]}...", "✓ Privé")
        if key_data.q:
            table.add_row("q", f"{str(key_data.q)[:30]}...", "✓ Privé")
        
        console.print(table)
    
    def _log(self, message: str, level: str = "INFO"):
        """Log si verbose"""
        if self.verbose:
            from rich.console import Console
            colors = {"INFO": "cyan", "WARNING": "yellow", "ERROR": "red"}
            Console().print(f"[{colors.get(level, 'white')}][{level}] KeyLoader: {message}[/{colors.get(level, 'white')}]")