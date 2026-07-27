"""
Verificador COMBINADO (solo LECTURA) de PPPoE y configuración ACS/TR-069
en un lote de routers. Hace UN solo login por router y chequea ambas cosas,
generando un único CSV con el resultado de las dos verificaciones.

IMPORTANTE: corre SECUENCIAL (no en paralelo) a propósito. prueba.py usa
ROUTER_BASE_URL como variable global del módulo, así que ejecutar varios
logins en paralelo genera una condición de carrera (un hilo pisa la URL
de otro a mitad de camino) y todo falla. Correr uno a la vez es la forma
segura de usar este login tal como está escrito.

Requiere prueba.py en la misma carpeta (reutiliza login()).
"""

import csv
import time
import requests

from prueba import login
import prueba as base

DELAY_ENTRE_ROUTERS = 1  # segundos
DOMINIO_ESPERADO = "@wsneo.com.py"
ACS_ESPERADO = "https://acs.neo.com.py:7547"

INPUT_CSV = "ips_online.csv"
OUTPUT_CSV = "verificacion_completa.csv"


def cargar_urls(path):
    urls = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"].rstrip("/"))
    return urls


def verificar_router(base_url: str):
    base.ROUTER_BASE_URL = base_url

    session = requests.Session()
    session.headers.update({
        "Origin": base_url,
        "X-Requested-With": "XMLHttpRequest",
        "_responseformat": "JSON",
    })

    resultado = {
        "url": base_url,
        "pppoe_username": "",
        "pppoe_ok": "",
        "acsserver_actual": "",
        "acs_ok": "",
        "estado": "OK",
        "detalle": "",
    }

    try:
        login(session)
    except requests.exceptions.ConnectionError:
        resultado.update(estado="ERROR", detalle="Conexión")
        return resultado
    except requests.exceptions.Timeout:
        resultado.update(estado="ERROR", detalle="Timeout")
        return resultado
    except RuntimeError as e:
        resultado.update(estado="ERROR", detalle=f"Login: {e}")
        return resultado
    except Exception as e:
        resultado.update(estado="ERROR", detalle=f"Inesperado en login: {e}")
        return resultado

    try:
        resp = session.get(f"{base_url}/api/ntwk/wan?type=active", verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        username = data.get("Username", "")
        resultado["pppoe_username"] = username
        resultado["pppoe_ok"] = "SI" if username.endswith(DOMINIO_ESPERADO) else "NO"
    except Exception as e:
        resultado["pppoe_ok"] = "ERROR"
        resultado["detalle"] += f"PPPoE: {e}; "

    try:
        resp = session.get(f"{base_url}/api/app/tr069", verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        acsserver_actual = data.get("acsserver", "")
        resultado["acsserver_actual"] = acsserver_actual
        resultado["acs_ok"] = "SI" if acsserver_actual == ACS_ESPERADO else "NO"
    except Exception as e:
        resultado["acs_ok"] = "ERROR"
        resultado["detalle"] += f"ACS: {e}; "

    return resultado


def main():
    urls = cargar_urls(INPUT_CSV)
    total = len(urls)
    print(f"Verificando {total} router(es) (secuencial)...\n")

    resultados = []
    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{total}] {url} ...", end=" ", flush=True)
        r = verificar_router(url)
        resultados.append(r)
        print(r["estado"], r["detalle"])

        if i < total:
            time.sleep(DELAY_ENTRE_ROUTERS)

    login_error = [r for r in resultados if r["estado"] == "ERROR"]
    pppoe_mal = [r for r in resultados if r["pppoe_ok"] == "NO"]
    acs_mal = [r for r in resultados if r["acs_ok"] == "NO"]

    print("\n===== RESUMEN =====")
    print(f"Total router(es):        {total}")
    print(f"Error de login/conexión: {len(login_error)}")
    print(f"PPPoE incorrecto:        {len(pppoe_mal)}")
    print(f"ACS no configurado:      {len(acs_mal)}")

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["url", "pppoe_username", "pppoe_ok", "acsserver_actual", "acs_ok", "estado", "detalle"],
        )
        writer.writeheader()
        for r in resultados:
            writer.writerow(r)

    print(f"\n[OK] Reporte completo guardado en {OUTPUT_CSV}")


if __name__ == "__main__":
    main()