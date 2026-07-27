"""
Cruza el PPPoE leído de cada router (pppoe_actual.csv, generado por
obtener_pppoe.py) contra la planilla de contratos (DATOS.csv) para obtener
el número de contrato (tag) asociado a cada IP.

La comparación se hace ignorando mayúsculas/minúsculas.

Genera cruce_contrato_ip.csv con: tag, pppoe, ip, match, onu_modelo,
ativo_acs, status_contrato.
"""

import csv

DATOS_CSV = "DATOS.csv"          # planilla de contratos (tag, pppoe, onu_modelo, ativo_acs, status_contrato)
PPPOE_ACTUAL_CSV = "pppoe_actual.csv"   # generado por obtener_pppoe.py (url, pppoe_actual, detalle)
OUTPUT_CSV = "cruce_contrato_ip.csv"


def extraer_ip(url: str) -> str:
    # https://100.90.77.30:1771 -> 100.90.77.30
    sin_esquema = url.replace("https://", "").replace("http://", "")
    return sin_esquema.split(":")[0]


def cargar_datos(path):
    """Devuelve un dict: pppoe_en_minuscula -> fila completa."""
    indice = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pppoe = (row.get("pppoe") or "").strip()
            if pppoe:
                indice[pppoe.lower()] = row
    return indice


def cargar_pppoe_actual(path):
    filas = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            filas.append(row)
    return filas


def main():
    print(f"Cargando planilla de contratos desde {DATOS_CSV}...")
    indice_contratos = cargar_datos(DATOS_CSV)
    print(f"  {len(indice_contratos)} contratos indexados.\n")

    print(f"Cargando PPPoE leídos desde {PPPOE_ACTUAL_CSV}...")
    filas_pppoe = cargar_pppoe_actual(PPPOE_ACTUAL_CSV)
    print(f"  {len(filas_pppoe)} routers cargados.\n")

    resultados = []
    con_match = 0
    sin_match = 0

    for fila in filas_pppoe:
        url = fila["url"]
        pppoe_actual = (fila.get("pppoe_actual") or "").strip()
        ip = url  # se guarda la URL completa, lista para usar en lista_ips.txt

        if not pppoe_actual:
            resultados.append({
                "tag": "",
                "pppoe": "",
                "ip": ip,
                "match": "SIN_PPPOE",
                "onu_modelo": "",
                "ativo_acs": "",
                "status_contrato": "",
            })
            sin_match += 1
            continue

        fila_contrato = indice_contratos.get(pppoe_actual.lower())

        if fila_contrato:
            resultados.append({
                "tag": fila_contrato.get("tag", ""),
                "pppoe": pppoe_actual,
                "ip": ip,
                "match": "SI",
                "onu_modelo": fila_contrato.get("onu_modelo", ""),
                "ativo_acs": fila_contrato.get("ativo_acs", ""),
                "status_contrato": fila_contrato.get("status_contrato", ""),
            })
            con_match += 1
        else:
            resultados.append({
                "tag": "",
                "pppoe": pppoe_actual,
                "ip": ip,
                "match": "NO",
                "onu_modelo": "",
                "ativo_acs": "",
                "status_contrato": "",
            })
            sin_match += 1

    print("===== RESUMEN =====")
    print(f"Con match (contrato encontrado): {con_match}")
    print(f"Sin match:                       {sin_match}")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["tag", "pppoe", "ip", "match", "onu_modelo", "ativo_acs", "status_contrato"],
        )
        writer.writeheader()
        for r in resultados:
            writer.writerow(r)

    print(f"\n[OK] Cruce guardado en {OUTPUT_CSV}")


if __name__ == "__main__":
    main()