"""
PRUEBA de corrección de PPPoE en UN SOLO router (para validar antes de
correrlo en lote). Cambia el Username si no termina en @wsneo.com.py,
y manda el valor literal "********" en Password -- la hipótesis es que
el router interpreta ese valor como "no cambiar la contraseña actual"
(patrón estándar de campo enmascarado como centinela).

IMPORTANTE: después de correr esto, verificá MANUALMENTE por el navegador
que el router siga conectado a Internet normalmente, antes de confiar en
este método para el resto del lote.
"""

import requests

from prueba import login, rsa_encrypt_oaep_chunked
import prueba as base

# ============ CONFIGURACIÓN ============
ROUTER_BASE_URL = "https://100.90.77.57:1771"  # <-- poné acá la IP del router de prueba
DOMINIO_ESPERADO = "@wsneo.com.py"
# ========================================


def corregir_username(username_actual: str) -> str:
    """Aplica la regla: si tiene otro dominio, se reemplaza; si no tiene
    dominio, se le agrega."""
    if "@" in username_actual:
        parte_usuario = username_actual.split("@")[0]
    else:
        parte_usuario = username_actual
    return parte_usuario + DOMINIO_ESPERADO


def main():
    base.ROUTER_BASE_URL = ROUTER_BASE_URL

    session = requests.Session()
    session.headers.update({
        "Origin": ROUTER_BASE_URL,
        "X-Requested-With": "XMLHttpRequest",
        "_responseformat": "JSON",
    })

    print("Haciendo login...")
    rsan, rsae, csrf = login(session)
    print("[OK] Login exitoso.\n")

    print("Leyendo configuración WAN actual...")
    resp = session.get(f"{ROUTER_BASE_URL}/api/ntwk/wan?type=active", verify=False, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    username_actual = data.get("Username", "")
    print(f"Username actual: {username_actual!r}")

    if username_actual.endswith(DOMINIO_ESPERADO):
        print("[INFO] Este router ya tiene el dominio correcto. No hace falta cambiar nada.")
        return

    username_nuevo = corregir_username(username_actual)
    print(f"Username nuevo:  {username_nuevo!r}")

    # Encriptar el centinela "********" como Password (hipótesis: el router
    # mantiene la contraseña real sin cambios al recibir este valor exacto)
    password_sentinel_encriptado = rsa_encrypt_oaep_chunked("********", rsan, rsae)

    data["Username"] = username_nuevo
    data["Password"] = password_sentinel_encriptado
    data["MacSelectValue"] = "none" if not data.get("MACColoneEnable") else data.get("MACColone", "")
    data["isLoadFinish"] = True

    payload = {
        "action": "update",
        "csrf": csrf,
        "data": data,
    }

    print("\nEnviando corrección...")
    resp = session.post(
        f"{ROUTER_BASE_URL}/api/ntwk/wan?type=active",
        json=payload,
        headers={
            "Content-Type": "application/json;charset=utf-8;enp",
            "Referer": f"{ROUTER_BASE_URL}/html/index.html",
        },
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    result = resp.json()
    print(f"Respuesta del router: {result}")

    if result.get("errcode") == 0:
        print("\n[OK] Guardado correctamente.")
    else:
        print("\n[ERROR] El router respondió con un error, revisar arriba.")
        return

    # Verificación posterior
    print("\nVerificando el cambio...")
    resp = session.get(f"{ROUTER_BASE_URL}/api/ntwk/wan?type=active", verify=False, timeout=10)
    resp.raise_for_status()
    data_verif = resp.json()
    print(f"Username después del cambio: {data_verif.get('Username')!r}")
    print(f"ConnectionStatus:            {data_verif.get('ConnectionStatus')!r}")

    print("\n[IMPORTANTE] Ahora verificá MANUALMENTE en el navegador que el router")
    print("siga conectado a Internet con normalidad, para confirmar que la")
    print("contraseña real no se rompió.")


if __name__ == "__main__":
    main()