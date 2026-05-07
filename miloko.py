#!/usr/bin/env python3

import os, sys, hashlib, shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature # Validor de hashes

BASE_DIR   = Path(__file__).parent
KEYS_DIR   = BASE_DIR / "firma_workspace/keys"
SIGNED_DIR = BASE_DIR / "firma_workspace/archivos_firmados"
W          = 80

#Funciones
def LH():   print("#" * W)
def hb():   print("# " + " " * (W - 4) + " #")
def hp(t):
    if len(t) > W - 4: t = t[:W - 7] + "..."
    print("# " + t.center(W - 4) + " #")

def cls():  os.system("cls" if os.name == "nt" else "clear")

def header(titulo):
    cls(); print()
    LH(); hp(titulo.upper()); LH()
    print()

def resultado(titulo, lineas):
    cls()
    LH(); hp(titulo); LH(); hb()
    for l in lineas: hp(l)
    hb(); LH()
    try: input("\n  > ")
    except KeyboardInterrupt: bye()

def error(msg):
    cls(); print()
    LH(); hp(msg); LH()
    try: input("\n  > ")
    except KeyboardInterrupt: bye()

def bye():
    cls(); print()
    LH(); hp("adio"); LH()
    print(); sys.exit(0)

def pedir(msg):
    try:    return input(f"  {msg}\n  > ").strip()
    except KeyboardInterrupt: bye()

def banner():
    cls(); print(); LH(); print()
    for l in [
        r"  ______ _                                  _   _       _         ",
        r" |  ____(_)                                (_) | |     | |        ",
        r" | |__   _ _ __ _ __ ___   __ _   _ __ ___  _  | | ___ | | _____  ",
        r" |  __| | | '__| '_ ` _ \ / _` | | '_ ` _ \| | | |/ _ \| |/ / _ \ ",
        r" | |    | | |  | | | | | | (_| | | | | | | | | | | (_) |   < (_) |",
        r" |_|    |_|_|  |_| |_| |_|\__,_| |_| |_| |_|_| |_|\___/|_|\_\___/",
    ]: print(l.center(W))
    print(); LH()

# Generar llaves
def generar_llaves():
    header("generar llaves rsa")
    pp = pedir("passphrase para la llave privada").encode() # String a bytes para cryptography
    if not pp:
        error("la passphrase no puede estar vacia"); return
    
# Llave priv

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048) # e = estandar, primo y seguro
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    (KEYS_DIR / "private_key.pem").write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, # 3, -----BEGIN/END----- base 64
        serialization.PrivateFormat.PKCS8, # 2 Almacena la llave priv 
        serialization.BestAvailableEncryption(pp) # 1 Aes 256
    ))

# Llave publica 
    (KEYS_DIR / "public_key.pem").write_bytes(priv.public_key().public_bytes(  # Extrae la llave publica del objet de la priv
        serialization.Encoding.PEM,  # Base64 cabeceras
        serialization.PublicFormat.SubjectPublicKeyInfo #  Formato x.509 sin cifrado
    ))
    resultado("llaves generadas correctamente", [
        "priv  :  firma_workspace/keys/private_key.pem",
        "pub   :  firma_workspace/keys/public_key.pem",
    ])

# Firmador de arshivos
def firmar_archivo():
    header("firmar archivo")

    archivos = [f for f in BASE_DIR.iterdir()
                if f.is_file() and f.suffix != ".py" and "firma_workspace" not in str(f)]
    if not archivos:
        error("No hay archivos en este directorio"); return

    LH(); hp("archivos disponibles"); LH(); hb()
    for i, f in enumerate(archivos, 1): hp(f"( {i} )  {f.name}")
    hb(); LH()

    try:
        sel = int(pedir("numero del archivo a firmar"))
        if not 1 <= sel <= len(archivos): raise ValueError
    except ValueError:
        error("seleccion invalida"); return

    target = archivos[sel - 1] # 0 python 1 iniciamos

    cls(); LH(); hp("firmar archivo"); LH(); print()
    ruta_priv = pedir("ruta llave privada PEM  [enter = default]") or str(KEYS_DIR / "private_key.pem")
    pp        = pedir("passphrase").encode()

    try:
        priv = serialization.load_pem_private_key(Path(ruta_priv).read_bytes(), password=pp)
    except Exception:
        error("passphrase incorrecta o llave invalida"); return

# PSS
    sig = priv.sign(target.read_bytes(), # Lee el contenido 
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), # Salt random para cada firma (Es unica) # mgf1 obligatorio para pss
                    hashes.SHA256())
    SIGNED_DIR.mkdir(parents=True, exist_ok=True)  
    (SIGNED_DIR / f"{target.name}.sig").write_bytes(sig) # Guardado del sig en bytes
    shutil.copy2(target, SIGNED_DIR / target.name) # Copia del archivo con sus metadatos con su fecha original

    resultado("archivo firmado correctamente", [
        f"orig  :  {target.name}",
        f"sig   :  {target.name}.sig",
        "dir   :  firma_workspace/archivos_firmados/",
    ])

# Verificador
def verificar_integridad():
    header("verificar integridad")

    sigs = list(SIGNED_DIR.glob("*.sig"))
    if not sigs:
        error("no hay archivos .sig disponibles"); return

    LH(); hp("firmas disponibles"); LH(); hb()
    for i, s in enumerate(sigs, 1): hp(f"( {i} )  {s.name}")
    hb(); LH()

    try:
        sel = int(pedir("numero del .sig a verificar"))
        if not 1 <= sel <= len(sigs): raise ValueError
    except ValueError:
        error("seleccion invalida"); return

    sig_path = sigs[sel - 1]
    original = SIGNED_DIR / sig_path.stem
    if not original.exists():
        original = Path(pedir("ruta del archivo original"))
        if not original.exists():
            error("archivo no encontrado"); return

    cls(); LH(); hp("verificar integridad"); LH(); print()
    ruta_pub = pedir("ruta llave publica PEM  [enter = default]") or str(KEYS_DIR / "public_key.pem") 
# Validación del hash
    pub  = serialization.load_pem_public_key(Path(ruta_pub).read_bytes()) #Carga la llave publica 
    data = original.read_bytes()# lee el contenido del archivo a verificar
    h    = hashlib.sha256(data).hexdigest() # calcula el hash

    try:
        pub.verify(sig_path.read_bytes(), data, # lee la firma del .sig y lo compara con el hash del original con el hash de ahora
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), # El mismo padding que usamos al firmar el archivo 
                   hashes.SHA256())
        estado = "archivo sin manipulacion"
    except InvalidSignature:
        estado = "ARCHIVO MANIPULADO"

    cls()
    LH(); hp("resultado de verificacion"); LH(); hb()
    hp(f"archivo  :  {original.name}")
    hp("sha-256  :"); hp(h[:32]); hp(h[32:])
    hb(); LH(); hp(estado); LH()
    try: input("\n  > ")
    except KeyboardInterrupt: bye()


def ver_hash():
    header("hash sha-256")
    ruta = pedir("ruta del archivo")
    if not ruta: error(" ruta vacia"); return

    path = Path(ruta)
    if not path.is_file(): error("archivo no encontrado"); return

    h = hashlib.sha256(path.read_bytes()).hexdigest()
    resultado("hash generado", [f"archivo  :  {path.name}", "sha-256  :", h[:32], h[32:]])


def menu():
    while True:
        banner(); print()
        LH(); hb()
        hp("( 1 )  generar llaves")
        hp("( 2 )  firmar archivo")
        hp("( 3 )  verificar integridad")
        hp("( 4 )  ver hash de archivo")
        hb(); hp("( 0 )  salir"); hb(); LH(); print()

        op = pedir("opcion")
        if   op == "1": generar_llaves()
        elif op == "2": firmar_archivo()
        elif op == "3": verificar_integridad()
        elif op == "4": ver_hash()
        elif op == "0": bye()
        else: error("[!]  opcion no valida")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        bye()