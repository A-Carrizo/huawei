"""
Configura ACS + corrige PPPoE para una lista de routers que vos mismo pegás
en lista_ips.txt (una URL por línea, formato https://IP:1771).

Corrige el bug de CSRF desactualizado: usa el csrf que devuelve el propio
guardado del ACS para el paso siguiente (PPPoE), en vez del csrf viejo
del login.

ADVERTENCIA: corregir el PPPoE corta la conexión del router hasta que se
autorice manualmente en el sistema de autenticación (RADIUS/CGNAT).
"""

import csv
import os
import time
import requests

from prueba import login, save_tr069_config, rsa_encrypt_oaep_chunked
import prueba as base

DELAY_ENTRE_ROUTERS = 3  # segundos
DOMINIO_ESPERADO = "@wsneo.com.py"

INPUT_FILE = "lista_ips.txt"
LOG_CSV = "resultado_acs_pppoe.csv"

CAMPOS = ["url", "acs_ok", "acs_detalle", "pppoe_cambiado", "pppoe_anterior", "pppoe_nuevo", "pppoe_detalle"]


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
    base.ROUTER_BASE_URL = base_url

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
        rsan, rsae, csrf = login(session)
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
        result_acs = save_tr069_config(session, rsan, rsae, csrf)
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