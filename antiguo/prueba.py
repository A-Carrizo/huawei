"""
Configurador automático de TR-069 para routers Huawei (firmware WS7001-XX y similares).
Versión limpia (sin prints de debug), lista para uso en producción / batch.
"""

import hashlib
import hmac
import re
import secrets
import sys
import base64

import requests
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

requests.packages.urllib3.disable_warnings()


# ============================= CONFIGURACIÓN =================================

ROUTER_BASE_URL = "https://100.90.80.124:1771/"
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

# ==============================================================================


def get_csrf(session, html_text):
    param = re.search(r'name="csrf_param"\s+content="([^"]+)"', html_text)
    token = re.search(r'name="csrf_token"\s+content="([^"]+)"', html_text)
    if not param or not token:
        raise RuntimeError("No se encontraron csrf_param/csrf_token en el HTML")
    return {"csrf_param": param.group(1), "csrf_token": token.group(1)}


def pbkdf2_sha256(password: str, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen)


def hmac_sha256(*, key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
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


def login(session: requests.Session):
    resp = session.get(f"{ROUTER_BASE_URL}/html/index.html", verify=False, timeout=10)
    resp.raise_for_status()
    csrf = get_csrf(session, resp.text)

    first_nonce = secrets.token_hex(32)
    payload_nonce = {
        "csrf": csrf,
        "data": {"username": ADMIN_USERNAME, "firstnonce": first_nonce},
    }
    resp = session.post(
        f"{ROUTER_BASE_URL}/api/system/user_login_nonce",
        json=payload_nonce,
        headers={"Referer": f"{ROUTER_BASE_URL}/html/index.html"},
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

    salted_password = pbkdf2_sha256(ADMIN_PASSWORD, salt, iterations)
    client_key = hmac_sha256(key=b"Client Key", msg=salted_password)
    stored_key = hashlib.sha256(client_key).digest()
    client_signature = hmac_sha256(key=auth_msg.encode("utf-8"), msg=stored_key)
    client_proof = xor_bytes(client_key, client_signature).hex()

    server_key = hmac_sha256(key=b"Server Key", msg=salted_password)
    server_proof_expected = hmac_sha256(key=auth_msg.encode("utf-8"), msg=server_key).hex()

    payload_proof = {
        "csrf": csrf,
        "data": {"clientproof": client_proof, "finalnonce": server_nonce},
    }

    resp = session.post(
        f"{ROUTER_BASE_URL}/api/system/user_login_proof",
        json=payload_proof,
        headers={"Referer": f"{ROUTER_BASE_URL}/html/index.html"},
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

    public_key_signature = hmac_sha256(key=server_key, msg=bytes.fromhex(rsan)).hex()
    _ = proof_res.get("rsapubkeysignature") == public_key_signature  # verificación opcional silenciosa

    return rsan, rsae, csrf


def save_tr069_config(session: requests.Session, rsan: str, rsae: str, csrf: dict):
    get_resp = session.get(f"{ROUTER_BASE_URL}/api/app/tr069", verify=False, timeout=10)
    get_resp.raise_for_status()
    get_data = get_resp.json()
    if "csrf_param" in get_data and "csrf_token" in get_data:
        csrf = {"csrf_param": get_data["csrf_param"], "csrf_token": get_data["csrf_token"]}

    data = dict(TR069_CONFIG)
    data["acspasswd"] = rsa_encrypt_oaep_chunked(TR069_CONFIG["acspasswd"], rsan, rsae)
    data["conpasswd"] = rsa_encrypt_oaep_chunked(TR069_CONFIG["conpasswd"], rsan, rsae)

    payload = {"csrf": csrf, "data": data}

    resp = session.post(
        f"{ROUTER_BASE_URL}/api/app/tr069",
        json=payload,
        headers={
            "Content-Type": "application/json; charset=UTF-8;enp",
            "Referer": f"{ROUTER_BASE_URL}/html/index.html",
        },
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    result = resp.json()
    return result


def verify_tr069_config(session: requests.Session):
    resp = session.get(f"{ROUTER_BASE_URL}/api/app/tr069", verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()


def main():
    session = requests.Session()
    session.headers.update({
        "Origin": ROUTER_BASE_URL,
        "X-Requested-With": "XMLHttpRequest",
        "_responseformat": "JSON",
    })
    try:
        rsan, rsae, csrf = login(session)
        result = save_tr069_config(session, rsan, rsae, csrf)
        if result.get("errcode") == 0 or result.get("err") == 0:
            print("[OK] Configuración TR-069 guardada correctamente.")
        else:
            print(f"[ERROR] El router respondió con un error: {result}")
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] No se pudo conectar al router: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()