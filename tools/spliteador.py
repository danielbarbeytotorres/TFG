#!/usr/bin/env python3
import json, os, re, sys, uuid

if len(sys.argv) != 3:
    print("Uso: python3 spliteador.py <informe_limpio.json> <carpeta_salida>")
    sys.exit(1)

input_json = sys.argv[1]
out_dir = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)

# Carga el informe limpio de OpenVAS
with open(input_json, "r", encoding="utf-8") as f:
    data = json.load(f)

target = data.get("target", "unknown")
results = data.get("results", [])

if not results:
    print("⚠️  No se encontraron vulnerabilidades en el JSON de entrada.")
    sys.exit(0)

count = 0
for vuln in results:
    # saltar resultados vacíos o sin nombre
    if not vuln or not vuln.get("name"):
        continue

    name = vuln.get("name", "unknown")
    safe_name = re.sub(r'[^A-Za-z0-9_]+', '_', name)[:40].strip('_')
    vuln_id = uuid.uuid4().hex[:8]

    filename = f"{count:03d}_{safe_name}_{vuln_id}.json"
    filepath = os.path.join(out_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f_out:
        json.dump({
            "target": target,
            "result": vuln
        }, f_out, indent=2, ensure_ascii=False)

    count += 1

print(f"[✔] Generados {count} JSONs individuales en {out_dir}")