import xml.etree.ElementTree as ET
import json

def parse_openvas_xml(xml_path, json_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # A veces el XML tiene doble <report> anidado, así que buscamos el que contiene <results>
    reports = root.findall(".//report")
    report = None
    for r in reports:
        if r.find("results") is not None:
            report = r
            break

    if report is None:
        raise ValueError("No se encontró el bloque principal <report> con resultados.")

    results = []

    for res in report.findall(".//result"):
        vuln = {}

        # Cosas básicas
        vuln["name"] = (res.findtext("name") or "").strip()
        vuln["host"] = (res.findtext("host") or "").strip()
        vuln["port"] = (res.findtext("port") or "").strip()
        vuln["threat"] = (res.findtext("threat") or "").strip()
        vuln["severity"] = (res.findtext("severity") or "").strip()

        # Nodo <nvt>
        nvt = res.find("nvt")
        if nvt is not None:
            vuln["family"] = (nvt.findtext("family") or "").strip()
            vuln["cvss"] = (nvt.findtext("cvss_base") or "").strip()

            # CVEs
            cves = []
            for ref in nvt.findall(".//ref[@type='cve']"):
                cves.append(ref.get("id"))
            if cves:
                vuln["cve"] = cves

            # Extraer tags (resumen, solución, impacto, etc.)
            tags = nvt.findtext("tags")
            if tags:
                tags_dict = {}
                for part in tags.split("|"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tags_dict[k.strip()] = v.strip()
                vuln.update(tags_dict)

            vuln["solution"] = (nvt.findtext("solution") or "").strip()

        # Limpiar campos vacíos
        vuln = {k: v for k, v in vuln.items() if v}
        results.append(vuln)

    output = {
        "target": report.findtext(".//target/name") or "unknown",
        "results_count": len(results),
        "results": results
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[✔] JSON generado correctamente en: {json_path}")


# === USO ===
# Sustituye las rutas por las tuyas reales:
# parse_openvas_xml("/home/kali/Desktop/informe.xml", "/home/kali/Desktop/informe_limpio.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Uso: python3 parse_openvas_xml.py <input.xml> <output.json>")
    else:
        parse_openvas_xml(sys.argv[1], sys.argv[2])