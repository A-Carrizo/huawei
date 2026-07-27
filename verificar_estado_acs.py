"""
Verificador (solo LECTURA) del estado de configuración TR-069 en un lote de routers.
Corre en paralelo y minimiza la salida por consola: solo muestra progreso y
el resumen final. Genera:
  - estado_acs.csv       -> detalle completo de todos los routers
  - pendientes.txt       -> solo las URLs que faltan configurar
"""

import csv
import concurrent.futures
import requests

from prueba import login, ADMIN_PASSWORD
import prueba as base

PORT = 1771
MAX_WORKERS = 15  # cuántos routers verificar en paralelo

ACS_ESPERADO = "https://acs.neo.com.py:7547"

INPUT_CSV = "ips_online.csv"
OUTPUT_CSV = "estado_acs.csv"
OUTPUT_PENDIENTES = "pendientes.txt"


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
        resp = session.get(f"{base_url}/api/app/tr069", verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        acsserver_actual = data.get("acsserver", "")
        ya_configurado = acsserver_actual == ACS_ESPERADO

        return {
            "url": base_url,
            "estado": "YA_CONFIGURADO" if ya_configurado else "PENDIENTE",
            "acsserver_actual": acsserver_actual,
            "enable": data.get("enable"),
            "detalle": "",
        }
    except requests.exceptions.ConnectionError:
        return {"url": base_url, "estado": "ERROR", "acsserver_actual": "", "enable": "", "detalle": "Conexión"}
    except requests.exceptions.Timeout:
        return {"url": base_url, "estado": "ERROR", "acsserver_actual": "", "enable": "", "detalle": "Timeout"}
    except RuntimeError as e:
        return {"url": base_url, "estado": "ERROR", "acsserver_actual": "", "enable": "", "detalle": f"Login: {e}"}
    except Exception as e:
        return {"url": base_url, "estado": "ERROR", "acsserver_actual": "", "enable": "", "detalle": f"Inesperado: {e}"}


def main():
    urls = cargar_urls(INPUT_CSV)
    total = len(urls)
    print(f"Verificando {total} router(es) en paralelo ({MAX_WORKERS} a la vez)...")

    resultados = []
    completados = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futuros = {executor.submit(verificar_router, url): url for url in urls}
        for futuro in concurrent.futures.as_completed(futuros):
            resultados.append(futuro.result())
            completados += 1
            print(f"\rProgreso: {completados}/{total}", end="", flush=True)

    print()

    ya_configurados = [r for r in resultados if r["estado"] == "YA_CONFIGURADO"]
    pendientes = [r for r in resultados if r["estado"] == "PENDIENTE"]
    errores = [r for r in resultados if r["estado"] == "ERROR"]

    print("\n===== RESUMEN =====")
    print(f"Ya configurados: {len(ya_configurados)}")
    print(f"Pendientes:      {len(pendientes)}")
    print(f"Errores:         {len(errores)}")

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "estado", "acsserver_actual", "enable", "detalle"])
        writer.writeheader()
        for r in resultados:
            writer.writerow(r)

    with open(OUTPUT_PENDIENTES, "w") as f:
        for r in pendientes:
            f.write(r["url"] + "\n")

    print(f"\n[OK] Detalle completo en {OUTPUT_CSV}")
    print(f"[OK] Lista de pendientes en {OUTPUT_PENDIENTES} ({len(pendientes)} router(es))")


if __name__ == "__main__":
    main()