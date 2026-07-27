"""
Verificador (solo LECTURA) del usuario PPPoE en un lote de routers.
Hace login y lee la config WAN activa de cada uno, chequeando que el
Username termine en "@wsneo.com.py". Genera un CSV solo con los que
están MAL, para corregirlos manualmente.

Requiere prueba.py en la misma carpeta (reutiliza login()).
"""

import csv
import concurrent.futures
import requests

from prueba import login
import prueba as base

MAX_WORKERS = 15
DOMINIO_ESPERADO = "@wsneo.com.py"

INPUT_CSV = "ips_online.csv"           # generado por check_conectividad.py
OUTPUT_CSV = "pppoe_incorrectos.csv"   # solo los que están mal
OUTPUT_CSV_TODOS = "pppoe_todos.csv"   # detalle completo, por si sirve


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

    try:
        login(session)
        resp = session.get(
            f"{base_url}/api/ntwk/wan?type=active",
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        username = data.get("Username", "")
        correcto = username.endswith(DOMINIO_ESPERADO)

        return {
            "url": base_url,
            "estado": "OK" if correcto else "INCORRECTO",
            "username": username,
            "detalle": "",
        }
    except requests.exceptions.ConnectionError:
        return {"url": base_url, "estado": "ERROR", "username": "", "detalle": "Conexión"}
    except requests.exceptions.Timeout:
        return {"url": base_url, "estado": "ERROR", "username": "", "detalle": "Timeout"}
    except RuntimeError as e:
        return {"url": base_url, "estado": "ERROR", "username": "", "detalle": f"Login: {e}"}
    except Exception as e:
        return {"url": base_url, "estado": "ERROR", "username": "", "detalle": f"Inesperado: {e}"}


def main():
    urls = cargar_urls(INPUT_CSV)
    total = len(urls)
    print(f"Verificando PPPoE en {total} router(es) en paralelo ({MAX_WORKERS} a la vez)...")

    resultados = []
    completados = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futuros = {executor.submit(verificar_router, url): url for url in urls}
        for futuro in concurrent.futures.as_completed(futuros):
            resultados.append(futuro.result())
            completados += 1
            print(f"\rProgreso: {completados}/{total}", end="", flush=True)

    print()

    ok = [r for r in resultados if r["estado"] == "OK"]
    incorrectos = [r for r in resultados if r["estado"] == "INCORRECTO"]
    errores = [r for r in resultados if r["estado"] == "ERROR"]

    print("\n===== RESUMEN =====")
    print(f"OK (dominio correcto): {len(ok)}")
    print(f"INCORRECTO:            {len(incorrectos)}")
    print(f"ERROR (no se pudo verificar): {len(errores)}")

    with open(OUTPUT_CSV_TODOS, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "estado", "username", "detalle"])
        writer.writeheader()
        for r in resultados:
            writer.writerow(r)

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "username"])
        writer.writeheader()
        for r in incorrectos:
            writer.writerow({"url": r["url"], "username": r["username"]})

    print(f"\n[OK] Detalle completo en {OUTPUT_CSV_TODOS}")
    print(f"[OK] Lista de PPPoE incorrectos en {OUTPUT_CSV} ({len(incorrectos)} router(es))")


if __name__ == "__main__":
    main()