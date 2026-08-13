"""
Escaneo de CONECTIVIDAD solamente (no hace login, no manda credenciales).
Verifica qué IPs de un rango tienen el puerto de gestión (1771) abierto,
para saber cuáles routers están online ANTES de intentar loguearse en ellos.

IMPORTANTE: usar únicamente sobre rangos de IP que administrás legítimamente
(tu ISP, tu propia infraestructura). Escanear IPs ajenas sin autorización
puede ser ilegal, independientemente de la intención.
"""

import socket
import ipaddress
import concurrent.futures
import csv

PORT = 1771
TIMEOUT = 3  # segundos

# Ajustar al rango real que administrás, en formato CIDR.
# Ejemplos: "100.90.44.0/24" (254 IPs), "100.90.44.0/28" (14 IPs)
RANGO = "100.87.49.0/24"

IP_LIST = [str(ip) for ip in ipaddress.ip_network(RANGO).hosts()]


def check_port(ip: str):
    try:
        with socket.create_connection((ip, PORT), timeout=TIMEOUT):
            return ip, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ip, False


def main():
    print(f"Verificando conectividad al puerto {PORT} en {len(IP_LIST)} IP(s)...\n")
    online = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_port, IP_LIST)
        for ip, is_open in results:
            status = "ONLINE" if is_open else "sin respuesta"
            print(f"  {ip:20s} -> {status}")
            if is_open:
                online.append(ip)

    print(f"\n{len(online)} de {len(IP_LIST)} IPs respondieron en el puerto {PORT}:")
    for ip in online:
        print(f"  - {ip}")

    with open("ips_online.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url"])  # encabezado
        for ip in online:
            writer.writerow([f"https://{ip}:{PORT}/"])
    print(f"\n[OK] Lista guardada en ips_online.csv ({len(online)} IPs)")

    output_file = "ips_online.txt"
    with open(output_file, "w") as f:
        for ip in online:
            f.write(ip + "\n")
    print(f"\n[OK] Lista guardada en {output_file}")


if __name__ == "__main__":
    main()