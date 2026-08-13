"""
Configura ACS + corrige PPPoE para una lista de routers que vos mismo pegás
en lista_ips.txt (una URL por línea, formato https://IP:1771).

AUTOCONTENIDO: no depende de prueba.py. Solo necesita, además de las
librerías estándar, los paquetes 'requests' y 'pycryptodome' instalados
(pip install requests pycryptodome).

Corrige el bug de CSRF desactualizado: usa el csrf que devuelve el propio
guardado del ACS para el paso siguiente (PPPoE), en vez del csrf viejo
del login.

ADVERTENCIA: corregir el PPPoE corta la conexión del router hasta que se
autorice manualmente en el sistema de autenticación (RADIUS/CGNAT).
"""

import base64
import csv
import hashlib
import hmac
import os
import re
import secrets
import time

import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

requests.packages.urllib3.disable_warnings()

# ============================= CONFIGURACIÓN =================================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "N&0telec0m"

TR069_CONFIG = {
    "enable": True,
    "acsserver": "https://acs.neo.com.py:7547",
    "acsuser": "admin",
    "acspasswd": "admin123",
    "conuser": "admin",
    "conpasswd": "admin123",
    "inform": True,
    "interval": "60",
}

DELAY_ENTRE_ROUTERS = 3  # segundos
DOMINIO_ESPERADO = "@wsneo.com.py"

INPUT_FILE = "lista_ips.txt"
LOG_CSV = "resultado_acs_pppoe.csv"

CAMPOS = ["url", "acs_ok", "acs_detalle", "pppoe_cambiado", "pppoe_anterior", "pppoe_nuevo", "pppoe_detalle"]

# ==============================================================================


# --------------------------- Auth / crypto (ex prueba.py) ---------------------

def _get_csrf(html_text: str) -> dict:
    param = re.search(r'name="csrf_param"\s+content="([^"]+)"', html_text)
    token = re.search(r'name="csrf_token"\s+content="([^"]+)"', html_text)
    if not param or not token:
        raise RuntimeError("No se encontraron csrf_param/csrf_token en el HTML")
    return {"csrf_param": param.group(1), "csrf_token": token.group(1)}


def _pbkdf2_sha256(password: str, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen)


def _hmac_sha256(*, key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def rsa_encrypt_oaep_chunked(plaintext: str, n_hex: str, e_hex: str) -> str:
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    key = RSA.construct((n, e))
    cipher = PKCS1_OAEP.new(key)

    b64_str = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
    chunk_size = len(n_hex) // 2 - 42

    result = ""
    i = 0
    while i * chunk_size < len(b64_str):
        chunk = b64_str[i * chunk_size: (i + 1) * chunk_size]
        ciphertext = cipher.encrypt(chunk.encode("ascii"))
        ct_hex = ciphertext.hex()
        if len(ct_hex) != len(n_hex):
            continue
        result += ct_hex
        i += 1
    return result


def login(session: requests.Session, base_url: str):
    """Login SCRAM contra el router. Devuelve (rsan, rsae, csrf)."""
    resp = session.get(f"{base_url}/html/index.html", verify=False, timeout=10)
    resp.raise_for_status()
    csrf = _get_csrf(resp.text)

    first_nonce = secrets.token_hex(32)
    payload_nonce = {
        "csrf": csrf,
        "data": {"username": ADMIN_USERNAME, "firstnonce": first_nonce},
    }
    resp = session.post(
        f"{base_url}/api/system/user_login_nonce",
        json=payload_nonce,
        headers={"Referer": f"{base_url}/html/index.html"},
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    nonce_res = resp.json()

    if nonce_res.get("err") != 0:
        raise RuntimeError(f"user_login_nonce falló: {nonce_res}")

    salt = bytes.fromhex(nonce_res["salt"])
    iterations = int(nonce_res["iterations"])
    server_nonce = nonce_res["servernonce"]
    csrf = {"csrf_param": nonce_res["csrf_param"], "csrf_token": nonce_res["csrf_token"]}

    auth_msg = f"{first_nonce},{server_nonce},{server_nonce}"

    salted_password = _pbkdf2_sha256(ADMIN_PASSWORD, salt, iterations)
    client_key = _hmac_sha256(key=b"Client Key", msg=salted_password)
    stored_key = hashlib.sha256(client_key).digest()
    client_signature = _hmac_sha256(key=auth_msg.encode("utf-8"), msg=stored_key)
    client_proof = _xor_bytes(client_key, client_signature).hex()

    payload_proof = {
        "csrf": csrf,
        "data": {"clientproof": client_proof, "finalnonce": server_nonce},
    }

    resp = session.post(
        f"{base_url}/api/system/user_login_proof",
        json=payload_proof,
        headers={"Referer": f"{base_url}/html/index.html"},
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    proof_res = resp.json()

    if proof_res.get("err") != 0:
        raise RuntimeError(f"user_login_proof falló (contraseña incorrecta?): {proof_res}")

    csrf = {"csrf_param": proof_res["csrf_param"], "csrf_token": proof_res["csrf_token"]}
    rsan = proof_res["rsan"]
    rsae = proof_res["rsae"]

    return rsan, rsae, csrf


def save_tr069_config(session: requests.Session, base_url: str, rsan: str, rsae: str, csrf: dict):
    get_resp = session.get(f"{base_url}/api/app/tr069", verify=False, timeout=10)
    get_resp.raise_for_status()
    get_data = get_resp.json()
    if "csrf_param" in get_data and "csrf_token" in get_data:
        csrf = {"csrf_param": get_data["csrf_param"], "csrf_token": get_data["csrf_token"]}

    data = dict(TR069_CONFIG)
    data["acspasswd"] = rsa_encrypt_oaep_chunked(TR069_CONFIG["acspasswd"], rsan, rsae)
    data["conpasswd"] = rsa_encrypt_oaep_chunked(TR069_CONFIG["conpasswd"], rsan, rsae)

    payload = {"csrf": csrf, "data": data}

    resp = session.post(
        f"{base_url}/api/app/tr069",
        json=payload,
        headers={
            "Content-Type": "application/json; charset=UTF-8;enp",
            "Referer": f"{base_url}/html/index.html",
        },
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()

# --------------------------------------------------------------------------


def cargar_urls(path):
    with open(path) as f:
        return [line.strip().rstrip("/") for line in f if line.strip()]


def corregir_username(username_actual: str) -> str:
    if "@" in username_actual:
        parte_usuario = username_actual.split("@")[0]
    else:
        parte_usuario = username_actual
    return parte_usuario + DOMINIO_ESPERADO


def procesar_router(base_url: str):
    resultado = {
        "url": base_url,
        "acs_ok": "",
        "acs_detalle": "",
        "pppoe_cambiado": "NO",
        "pppoe_anterior": "",
        "pppoe_nuevo": "",
        "pppoe_detalle": "",
    }

    session = requests.Session()
    session.headers.update({
        "Origin": base_url,
        "X-Requested-With": "XMLHttpRequest",
        "_responseformat": "JSON",
    })

    # --- Login ---
    try:
        rsan, rsae, csrf = login(session, base_url)
    except requests.exceptions.ConnectionError as e:
        resultado["acs_ok"] = "ERROR"
        resultado["acs_detalle"] = f"Conexión: {e}"
        return resultado
    except requests.exceptions.Timeout as e:
        resultado["acs_ok"] = "ERROR"
        resultado["acs_detalle"] = f"Timeout: {e}"
        return resultado
    except RuntimeError as e:
        resultado["acs_ok"] = "ERROR"
        resultado["acs_detalle"] = f"Login: {e}"
        return resultado
    except Exception as e:
        resultado["acs_ok"] = "ERROR"
        resultado["acs_detalle"] = f"Inesperado en login: {e}"
        return resultado

    # --- Configurar ACS ---
    try:
        result_acs = save_tr069_config(session, base_url, rsan, rsae, csrf)
        if result_acs.get("errcode") == 0 or result_acs.get("err") == 0:
            resultado["acs_ok"] = "OK"
        else:
            resultado["acs_ok"] = "ERROR"
            resultado["acs_detalle"] = f"Router respondió: {result_acs}"

        # CLAVE: actualizar el csrf con el que devolvió este POST,
        # si no, el siguiente paso (PPPoE) usa un csrf ya vencido.
        if result_acs.get("csrf_param") and result_acs.get("csrf_token"):
            csrf = {
                "csrf_param": result_acs["csrf_param"],
                "csrf_token": result_acs["csrf_token"],
            }
    except Exception as e:
        resultado["acs_ok"] = "ERROR"
        resultado["acs_detalle"] = f"Guardando ACS: {e}"
        return resultado  # si falla el ACS, no seguimos con PPPoE en este router

    # --- Verificar / corregir PPPoE ---
    try:
        resp = session.get(f"{base_url}/api/ntwk/wan?type=active", verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        username_actual = data.get("Username", "")
        resultado["pppoe_anterior"] = username_actual

        if username_actual.endswith(DOMINIO_ESPERADO):
            resultado["pppoe_cambiado"] = "NO"
            resultado["pppoe_nuevo"] = username_actual
        else:
            username_nuevo = corregir_username(username_actual)
            password_sentinel = rsa_encrypt_oaep_chunked("********", rsan, rsae)

            data["Username"] = username_nuevo
            data["Password"] = password_sentinel
            data["MacSelectValue"] = "none" if not data.get("MACColoneEnable") else data.get("MACColone", "")
            data["isLoadFinish"] = True

            payload = {"action": "update", "csrf": csrf, "data": data}

            resp = session.post(
                f"{base_url}/api/ntwk/wan?type=active",
                json=payload,
                headers={
                    "Content-Type": "application/json;charset=utf-8;enp",
                    "Referer": f"{base_url}/html/index.html",
                },
                verify=False,
                timeout=15,
            )
            resp.raise_for_status()
            result_pppoe = resp.json()

            if result_pppoe.get("errcode") == 0:
                resultado["pppoe_cambiado"] = "SI"
                resultado["pppoe_nuevo"] = username_nuevo
            else:
                resultado["pppoe_cambiado"] = "ERROR"
                resultado["pppoe_detalle"] = f"Router respondió: {result_pppoe}"

    except Exception as e:
        resultado["pppoe_cambiado"] = "ERROR"
        resultado["pppoe_detalle"] = f"{e}"

    return resultado


def main():
    urls = cargar_urls(INPUT_FILE)
    print(f"Procesando {len(urls)} router(es) desde {INPUT_FILE}...\n")

    escribir_header = not os.path.exists(LOG_CSV)

    with open(LOG_CSV, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CAMPOS)
        if escribir_header:
            writer.writeheader()

        for i, url in enumerate(urls, start=1):
            print(f"[{i}/{len(urls)}] {url} ...")
            r = procesar_router(url)
            writer.writerow(r)
            f.flush()

            print(f"    ACS: {r['acs_ok']} {r['acs_detalle']}")
            print(f"    PPPoE: {r['pppoe_cambiado']} "
                  f"(antes: {r['pppoe_anterior']!r} -> ahora: {r['pppoe_nuevo']!r}) {r['pppoe_detalle']}")

            if i < len(urls):
                time.sleep(DELAY_ENTRE_ROUTERS)

    print(f"\n[OK] Resultados guardados/acumulados en {LOG_CSV}")


if __name__ == "__main__":
    main()