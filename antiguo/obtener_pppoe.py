"""
Lee (SOLO LECTURA, no modifica nada) el Username PPPoE actual de cada
router en ips_online.csv. Genera un CSV con url + pppoe_actual, listo
para cruzar con la planilla de contratos.
"""

import csv
import time
import requests

from prueba import login
import prueba as base

DELAY_ENTRE_ROUTERS = 2  # segundos

INPUT_CSV = "ips_online.csv"
OUTPUT_CSV = "pppoe_actual.csv"


def cargar_urls(path):
    urls = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"].rstrip("/"))
    return urls


def leer_pppoe(base_url: str):
    base.ROUTER_BASE_URL = base_url

    session = requests.Session()
    session.headers.update({
        "Origin": base_url,
        "X-Requested-With": "XMLHttpRequest",
        "_responseformat": "JSON",
    })

    try:
        login(session)
        resp = session.get(f"{base_url}/api/ntwk/wan?type=active", verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return {"url": base_url, "pppoe_actual": data.get("Username", ""), "detalle": ""}
    except requests.exceptions.ConnectionError as e:
        return {"url": base_url, "pppoe_actual": "", "detalle": f"Conexión: {e}"}
    except requests.exceptions.Timeout as e:
        return {"url": base_url, "pppoe_actual": "", "detalle": f"Timeout: {e}"}
    except RuntimeError as e:
        return {"url": base_url, "pppoe_actual": "", "detalle": f"Login: {e}"}
    except Exception as e:
        return {"url": base_url, "pppoe_actual": "", "detalle": f"Inesperado: {e}"}


def main():
    urls = cargar_urls(INPUT_CSV)
    total = len(urls)
    print(f"Leyendo PPPoE de {total} router(es)...\n")

    resultados = []
    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{total}] {url} ...", end=" ", flush=True)
        r = leer_pppoe(url)
        resultados.append(r)
        print(r["pppoe_actual"] or f"ERROR: {r['detalle']}")

        if i < total:
            time.sleep(DELAY_ENTRE_ROUTERS)

    ok = [r for r in resultados if r["pppoe_actual"]]
    error = [r for r in resultados if not r["pppoe_actual"]]

    print(f"\n===== RESUMEN =====")
    print(f"Leídos correctamente: {len(ok)}")
    print(f"Con error:            {len(error)}")

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "pppoe_actual", "detalle"])
        writer.writeheader()
        for r in resultados:
            writer.writerow(r)

    print(f"\n[OK] Guardado en {OUTPUT_CSV}")


if __name__ == "__main__":
    main()