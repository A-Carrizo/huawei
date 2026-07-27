"""
Aplica la configuración TR-069 a TODOS los routers listados en ips_online.csv
(generado por check_conectividad.py), sin pasar por el chequeo de "pendientes".
Va uno por uno, con pausa entre cada uno, y nunca corta el proceso si alguno
falla -- sigue con el resto y deja un reporte final.

NOTA: los routers que usan un esquema de login distinto al SCRAM (los que
dieron 'errcode: 1' en user_login_nonce) van a seguir fallando acá hasta que
se implemente el login legado como fallback.
"""

import csv
import time
import requests

from prueba import login, save_tr069_config
import prueba as base

PORT = 1771
DELAY_ENTRE_ROUTERS = 3  # segundos

INPUT_CSV = "ips_online.csv"
OUTPUT_CSV = "resultado_configuracion.csv"


def cargar_urls(path):
    urls = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"].rstrip("/"))
    return urls


def configurar_router(base_url: str):
    base.ROUTER_BASE_URL = base_url

    session = requests.Session()
    session.headers.update({
        "Origin": base_url,
        "X-Requested-With": "XMLHttpRequest",
        "_responseformat": "JSON",
    })

    try:
        rsan, rsae, csrf = login(session)
        result = save_tr069_config(session, rsan, rsae, csrf)

        if result.get("errcode") == 0 or result.get("err") == 0:
            return {"url": base_url, "estado": "OK", "detalle": ""}
        else:
            return {"url": base_url, "estado": "ERROR", "detalle": f"Router respondió: {result}"}

    except requests.exceptions.ConnectionError as e:
        return {"url": base_url, "estado": "ERROR", "detalle": f"Conexión: {e}"}
    except requests.exceptions.Timeout as e:
        return {"url": base_url, "estado": "ERROR", "detalle": f"Timeout: {e}"}
    except RuntimeError as e:
        return {"url": base_url, "estado": "ERROR", "detalle": f"Login: {e}"}
    except Exception as e:
        return {"url": base_url, "estado": "ERROR", "detalle": f"Inesperado: {e}"}


def main():
    urls = cargar_urls(INPUT_CSV)
    total = len(urls)
    print(f"Configurando {total} router(es) desde {INPUT_CSV}...\n")

    resultados = []
    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{total}] {url} ...", end=" ", flush=True)
        r = configurar_router(url)
        resultados.append(r)
        print(r["estado"], r["detalle"])

        if i < total:
            time.sleep(DELAY_ENTRE_ROUTERS)

    ok = [r for r in resultados if r["estado"] == "OK"]
    error = [r for r in resultados if r["estado"] == "ERROR"]

    print("\n===== RESUMEN =====")
    print(f"OK:    {len(ok)}")
    print(f"ERROR: {len(error)}")

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "estado", "detalle"])
        writer.writeheader()
        for r in resultados:
            writer.writerow(r)

    print(f"\n[OK] Reporte guardado en {OUTPUT_CSV}")


if __name__ == "__main__":
    main()