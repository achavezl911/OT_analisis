#!/usr/bin/env python3
"""
Analiza capturas de red (pcap / pcapng / cap) desde el punto de vista OT y genera
un reporte de assessment.

Pensado para responder tres preguntas de un assessment en planta:

  1. Que hay realmente en la red (activos, protocolos, quien manda a quien).
  2. Que evidencia hay de riesgo (higiene, exposicion, comandos de control, anomalias).
  3. Por que una herramienta pasiva reporta hallazgos sobre estas capturas y otra no
     (seccion "brecha de visibilidad": truncamiento, SPAN unidireccional, ausencia de
     paquetes de identidad, etc.).

Uso:
    python ot_pcap_assess.py captura.pcapng
    python ot_pcap_assess.py carpeta_de_capturas/ -o reporte/
    python ot_pcap_assess.py *.pcapng --max-packets 0        # sin muestreo

Requiere Wireshark instalado (tshark y capinfos en el PATH, o --tshark).
"""

from __future__ import annotations

import argparse
import collections
import csv
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from html import escape as esc
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
# Localizacion de las herramientas de Wireshark
# --------------------------------------------------------------------------- #

WIRESHARK_DIRS = [
    # Windows
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
    # Linux
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/snap/bin",
    "/var/lib/flatpak/exports/bin",
    # macOS
    "/opt/homebrew/bin",
    "/usr/local/opt/wireshark/bin",
    "/Applications/Wireshark.app/Contents/MacOS",
]

INSTALL_HINT = {
    "linux": "instala el paquete 'tshark' (Debian/Ubuntu: sudo apt install tshark; "
             "RHEL/Rocky: sudo dnf install wireshark-cli)",
    "darwin": "instala Wireshark (brew install --cask wireshark)",
}.get(sys.platform, "instala Wireshark")


def find_tool(name: str, override: str | None = None) -> str:
    if override:
        p = Path(override)
        if p.is_dir():
            for cand in (p / name, p / f"{name}.exe"):
                if cand.exists():
                    return str(cand)
        elif p.exists():
            return str(p)
        sys.exit(f"[!] No encuentro {name} en {override}")
    found = shutil.which(name)
    if found:
        return found
    for d in WIRESHARK_DIRS:
        for cand in (Path(d) / name, Path(d) / f"{name}.exe"):
            if cand.exists():
                return str(cand)
    sys.exit(
        f"[!] No encuentro '{name}'. {INSTALL_HINT}, o pasa --tshark con la "
        f"ruta de la carpeta que lo contiene."
    )


def run(cmd: list[str], timeout: int = 7200) -> tuple[int, str, str]:
    p = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", timeout=timeout
    )
    return p.returncode, p.stdout, p.stderr


# --------------------------------------------------------------------------- #
# Campos y filtros (se validan contra el tshark instalado antes de usarse)
# --------------------------------------------------------------------------- #

# Pase 1: flujos. Pocos campos, se corre sobre muchos paquetes.
FLOW_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "eth.src_resolved",
    "eth.dst_resolved",
    "vlan.id",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "_ws.col.protocol",
]

# Pase 2: detalle. Muchos campos, pero solo sobre los paquetes que filtramos.
DETAIL_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "eth.src",
    "eth.src_resolved",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "vlan.id",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "_ws.col.protocol",
    # --- identidad de equipos (esto es lo que alimenta un match de CVE) ---
    "cdp.deviceid",
    "cdp.software_version",
    "cdp.platform",
    "cdp.portid",
    "lldp.tlv.system.name",
    "lldp.tlv.system.desc",
    "lldp.port.id",
    "lldp.port.desc",
    "http.server",
    "http.user_agent",
    "http.host",
    "http.request.uri",
    "http.authorization",
    "http.response.code",
    "snmp.community",
    "snmp.msgVersion",
    "dhcp.option.hostname",
    "dhcp.option.vendor_class_id",
    "nbns.name",
    "browser.server",
    "dns.qry.name",
    "smb.native_os",
    "smb2.buffer_code",
    "ntlmssp.auth.username",
    "ntlmssp.auth.domain",
    "kerberos.CNameString",
    "tls.handshake.version",
    "tls.handshake.extensions_server_name",
    # --- texto claro / credenciales ---
    "ftp.request.command",
    "ftp.request.arg",
    "telnet.data",
    "tftp.source_file",
    "tftp.destination_file",
    "syslog.msg",
    # --- protocolos OT ---
    "enip.command",
    "cip.service",
    "cip.class",
    "cip.symbol",
    "modbus.func_code",
    "modbus.reference_num",
    "dnp3.al.func",
    "dnp3.src",
    "dnp3.dst",
    "iec60870_asdu.typeid",
    "iec60870_asdu.causetx",
    "s7comm.param.func",
    "s7comm.header.rosctr",
    "goose.goID",
    "goose.stNum",
    "goose.sqNum",
    "mms.confirmedServiceRequest",
    "bacapp.confirmed_service",
    "opcua.servicenodeid",
    "pn_dcp.service_id",
    # --- L2 / anomalias ---
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "arp.duplicate-address-detected",
    "icmp.type",
    "icmp.code",
    "stp.flags.tc",
    "stp.root.hw",
]

# Cada pieza se valida por separado; las que el tshark local no entienda se descartan.
DETAIL_FILTER_PARTS = [
    "cdp",
    "lldp",
    "pn_dcp",
    "arp",
    "dhcp",
    "nbns",
    "browser",
    "snmp",
    "syslog",
    "telnet",
    "ftp",
    "tftp",
    "http",
    "dns",
    "ntlmssp",
    "kerberos",
    "smb",
    "smb2",
    "tls.handshake.type == 1",
    "tls.handshake.type == 2",
    "icmp.type == 3",
    "icmp.type == 5",
    "icmp.type == 8",
    "icmp.type == 13",
    "stp.flags.tc == 1",
    # OT: identidad y comandos; se excluye a proposito la lectura ciclica
    "enip.command in {0x0063, 0x0064, 0x0065, 0x0066, 0x006f}",
    "cip.class == 0x01",
    "cip.service in {0x01, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0d, 0x0e, 0x10, 0x4d, 0x4e, 0x53}",
    "modbus.func_code in {5, 6, 8, 15, 16, 20, 21, 22, 23, 43}",
    "dnp3.al.func in {1, 3, 4, 5, 6, 7, 13, 14, 18, 20, 21, 23, 25, 27, 31, 32}",
    "iec60870_asdu.typeid >= 45",
    "s7comm",
    "goose",
    "mms",
    "bacapp",
    "opcua",
]

# Puertos OT y de interes. (puerto, proto) -> (nombre, categoria)
OT_PORTS: dict[tuple[int, str], tuple[str, str]] = {
    (502, "tcp"): ("Modbus/TCP", "ot"),
    (802, "tcp"): ("Modbus/TCP seguro", "ot"),
    (20000, "tcp"): ("DNP3", "ot"),
    (20000, "udp"): ("DNP3", "ot"),
    (2404, "tcp"): ("IEC 60870-5-104", "ot"),
    (102, "tcp"): ("IEC 61850 MMS / S7comm (ISO-TSAP)", "ot"),
    (44818, "tcp"): ("EtherNet/IP explicito (CIP)", "ot"),
    (2222, "udp"): ("EtherNet/IP I/O ciclico (CIP Class 1)", "ot"),
    (44818, "udp"): ("EtherNet/IP descubrimiento", "ot"),
    (4840, "tcp"): ("OPC UA", "ot"),
    (4843, "tcp"): ("OPC UA sobre TLS", "ot"),
    (135, "tcp"): ("DCOM / OPC DA (endpoint mapper)", "ot"),
    (47808, "udp"): ("BACnet/IP", "ot"),
    (1962, "tcp"): ("PCWorx", "ot"),
    (9600, "tcp"): ("OMRON FINS", "ot"),
    (5007, "tcp"): ("Mitsubishi MELSEC", "ot"),
    (1911, "tcp"): ("Niagara Fox", "ot"),
    (789, "tcp"): ("Red Lion / Crimson", "ot"),
    (18245, "tcp"): ("GE SRTP", "ot"),
    (20547, "tcp"): ("ProConOS", "ot"),
    (34962, "udp"): ("PROFINET RT", "ot"),
    (34963, "udp"): ("PROFINET RT", "ot"),
    (34964, "udp"): ("PROFINET CM", "ot"),
    (319, "udp"): ("PTP evento (IEEE 1588)", "ot"),
    (320, "udp"): ("PTP general (IEEE 1588)", "ot"),
    # Gestion / IT que en OT merece revision
    (23, "tcp"): ("Telnet", "claro"),
    (21, "tcp"): ("FTP", "claro"),
    (69, "udp"): ("TFTP", "claro"),
    (80, "tcp"): ("HTTP", "claro"),
    (161, "udp"): ("SNMP", "claro"),
    (162, "udp"): ("SNMP trap", "claro"),
    (512, "tcp"): ("rexec", "claro"),
    (513, "tcp"): ("rlogin", "claro"),
    (514, "tcp"): ("rsh", "claro"),
    (514, "udp"): ("Syslog", "claro"),
    (139, "tcp"): ("NetBIOS sesion (SMB)", "it"),
    (445, "tcp"): ("SMB", "it"),
    (137, "udp"): ("NetBIOS nombres (NBT-NS)", "it"),
    (138, "udp"): ("NetBIOS datagrama", "it"),
    (5355, "udp"): ("LLMNR", "it"),
    (5353, "udp"): ("mDNS", "it"),
    (1900, "udp"): ("SSDP / UPnP", "it"),
    (3389, "tcp"): ("RDP", "it"),
    (5900, "tcp"): ("VNC", "it"),
    (22, "tcp"): ("SSH", "it"),
    (443, "tcp"): ("HTTPS", "it"),
    (1947, "udp"): ("Sentinel HASP / licenciamiento", "it"),
    (1947, "tcp"): ("Sentinel HASP / licenciamiento", "it"),
    (520, "udp"): ("RIP", "it"),
    (67, "udp"): ("DHCP servidor", "it"),
    (68, "udp"): ("DHCP cliente", "it"),
    (123, "udp"): ("NTP", "it"),
    (53, "udp"): ("DNS", "it"),
}

# Fabricantes tipicos de OT, por prefijo del nombre que resuelve Wireshark.
OT_VENDORS = {
    "rockwell": "Rockwell Automation / Allen-Bradley",
    "siemens": "Siemens",
    "schneider": "Schneider Electric",
    "powermeasure": "Schneider Electric / Power Measurement (ION)",
    "abb": "ABB",
    "generalelectric": "General Electric",
    "ge": "General Electric",
    "schweitzer": "SEL (Schweitzer)",
    "hirschmann": "Hirschmann (Belden)",
    "moxa": "Moxa",
    "phoenixcon": "Phoenix Contact",
    "beckhoff": "Beckhoff",
    "omron": "Omron",
    "mitsubish": "Mitsubishi Electric",
    "yokogawa": "Yokogawa",
    "honeywell": "Honeywell",
    "emerson": "Emerson",
    "wago": "WAGO",
    "advantech": "Advantech",
    "redlion": "Red Lion",
    "prosoft": "ProSoft",
    "woodward": "Woodward",
    "sel": "SEL (Schweitzer)",
    "cisco": "Cisco",
    "westermo": "Westermo",
}

SWITCH_HINTS = ("hirschmann", "cisco", "moxa", "westermo", "scalance", "ruggedcom")

# Cadenas de software que ya no tienen soporte o que conviene revisar siempre.
OBSOLETE_PATTERNS = [
    (r"WinCE|Windows CE", "Windows CE", "Fuera de soporte de Microsoft."),
    (r"Windows NT 5\.1|Windows XP", "Windows XP", "Fuera de soporte desde 2014."),
    (r"Windows NT 6\.0|Windows Vista", "Windows Vista", "Fuera de soporte desde 2017."),
    (r"Windows NT 6\.1|Windows 7", "Windows 7", "Fuera de soporte desde 2020."),
    (r"Windows Server 2003", "Windows Server 2003", "Fuera de soporte desde 2015."),
    (r"Windows Server 2008", "Windows Server 2008/R2", "Fuera de soporte desde 2020."),
    (r"SMBv1|NT LM 0\.12", "SMBv1", "Protocolo obsoleto, deshabilitarlo."),
    (r"OpenSSH_[1-6]\.", "OpenSSH anterior a 7.x", "Version antigua."),
    (r"Apache/1\.|Apache/2\.[0-2]\.", "Apache httpd antiguo", "Version antigua."),
    (r"IIS/[1-7]\.", "IIS antiguo", "Version antigua."),
    (r"lighttpd/1\.4\.[0-3]?[0-9]\b", "lighttpd antiguo", "Comun en firmware embebido."),
    (r"BusyBox", "BusyBox", "Firmware embebido; revisar version."),
]

SEV_ORDER = {"Alta": 0, "Media": 1, "Baja": 2, "Informativa": 3}

# Causas por las que dos plataformas pasivas difieren. (etiqueta, titulo del hallazgo)
VIS_CHECKS = [
    ("Captura truncada (snaplen corto)",
     "Captura truncada (snaplen por debajo del MTU)"),
    ("SPAN o TAP en un solo sentido",
     "La mayoria de las conversaciones aparece en un solo sentido"),
    ("Sin paquetes de identidad en la ventana",
     "La captura no contiene ningun paquete que revele identidad de equipos"),
    ("Pocos paquetes de identidad",
     "Muy pocos paquetes de identidad en la captura"),
    ("Trafico dominado por I/O ciclico",
     "El trafico es casi todo I/O ciclico, que no revela identidad"),
    ("Ventana de captura corta", "Ventana de captura corta"),
    ("Etiqueta VLAN ausente en el punto de captura",
     "Sin segmentacion por VLAN visible en el punto de captura"),
    ("Paquetes duplicados por SPAN", "Paquetes duplicados en la captura"),
    ("El punto de captura solo ve difusion y multicast",
     "El punto de captura casi no ve trafico unicast"),
]

VERIFY_WITH_CLIENT = [
    "<strong>Punto de captura distinto.</strong> Si la otra herramienta se "
    "conecto a otro SPAN, ve otro trafico. Hay que comparar el inventario de "
    "cada una, no el conteo de hallazgos.",
    "<strong>Sondeo activo habilitado o no.</strong> Las plataformas OT "
    "identifican firmware de dos formas: pasiva y por sondeo activo controlado. "
    "Si una lo tiene encendido y la otra no, la primera enumera CVEs y la "
    "segunda no, sobre exactamente la misma red.",
    "<strong>Taxonomia distinta.</strong> Lo que una herramienta llama "
    "'vulnerabilidad' otra lo reporta como alerta de higiene, riesgo de "
    "configuracion o un atributo del activo. Hay que comparar hallazgo por "
    "hallazgo, no los totales.",
    "<strong>Modo aprendizaje.</strong> Un sensor en fase de linea base no "
    "alerta, por diseno.",
    "<strong>Activos sin modelo ni firmware resuelto.</strong> Si el sensor no "
    "determino modelo y version, no puede asociar CVEs aunque el activo este "
    "en su inventario. Conviene revisar cuantos nodos tiene con esos campos "
    "vacios: ese numero es el diagnostico.",
]

CLIENT_QUESTIONS = [
    "En que punto exacto se tomaron estas capturas y donde esta conectado cada "
    "sensor. Si no es el mismo punto, la comparacion no es valida.",
    "La otra herramienta, hace sondeo activo? Estaba habilitado durante el analisis?",
    "Puede compartir el reporte de la otra herramienta con el detalle de cada "
    "hallazgo, para distinguir CVEs sobre firmware de hallazgos de higiene?",
    "Cuantos activos tiene cada plataforma en inventario, y cuantos de ellos "
    "con fabricante, modelo y firmware resueltos?",
    "Que ventana de tiempo cubrio cada analisis?",
    "El SPAN esta configurado en ambos sentidos y preserva las etiquetas VLAN?",
    "Hubo actividad de ingenieria o mantenimiento durante la ventana de captura?",
    "El sensor sigue en modo aprendizaje o ya paso a produccion?",
]


# --------------------------------------------------------------------------- #
# Validacion de campos y filtros contra el tshark instalado
# --------------------------------------------------------------------------- #


class Tshark:
    def __init__(self, tshark: str, capinfos: str, editcap: str, probe_dir: Path):
        self.tshark = tshark
        self.capinfos_bin = capinfos
        self.editcap = editcap
        self.probe_dir = probe_dir
        self.probe: Path | None = None

    def make_probe(self, sample: Path) -> None:
        """Un archivo de 1 paquete para validar filtros rapido."""
        self.probe_dir.mkdir(parents=True, exist_ok=True)
        probe = self.probe_dir / "probe.pcapng"
        rc, _, _ = run(
            [self.editcap, "-r", str(sample), str(probe), "1-1"], timeout=300
        )
        self.probe = probe if rc == 0 and probe.exists() else None

    def valid_fields(self, fields: list[str]) -> list[str]:
        """Quita los campos que este tshark no conoce, leyendo su propio error."""
        if not self.probe:
            return fields
        fields = list(fields)
        for _ in range(12):
            cmd = [self.tshark, "-r", str(self.probe), "-T", "fields"]
            for f in fields:
                cmd += ["-e", f]
            rc, _, err = run(cmd, timeout=120)
            if rc == 0:
                return fields
            bad = re.findall(r"^\s*\t?([\w._-]+)\s*$", err, re.M)
            bad = [b for b in bad if b in fields]
            if not bad:
                # No logramos identificar el campo malo; devolvemos un minimo seguro.
                return [f for f in fields if f.startswith(("frame.", "eth.", "ip."))]
            fields = [f for f in fields if f not in bad]
        return fields

    def valid_filter(self, parts: list[str]) -> str:
        """Arma el filtro con las piezas que compilan en este tshark."""
        if not self.probe:
            return " || ".join(f"({p})" for p in parts)
        ok = []
        for p in parts:
            rc, _, _ = run(
                [self.tshark, "-r", str(self.probe), "-Y", p, "-c", "1", "-q"],
                timeout=60,
            )
            if rc == 0:
                ok.append(p)
        return " || ".join(f"({p})" for p in ok) if ok else "frame"

    def fields_pass(
        self, path: Path, fields: list[str], dfilter: str | None, limit: int
    ):
        cmd = [self.tshark, "-r", str(path), "-n", "-N", "m", "-T", "fields",
               "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|"]
        for f in fields:
            cmd += ["-e", f]
        if dfilter:
            cmd += ["-Y", dfilter]
        if limit:
            cmd += ["-c", str(limit)]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="replace", bufsize=1 << 20,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.rstrip("\n").split("\t")
        proc.wait()

    def capinfos(self, path: Path) -> dict:
        rc, out, _ = run([self.capinfos_bin, "-M", str(path)], timeout=1800)
        info = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return info

    def phs(self, path: Path) -> dict[str, int]:
        rc, out, _ = run([self.tshark, "-r", str(path), "-q", "-z", "io,phs"], timeout=7200)
        protos: dict[str, int] = {}
        for line in out.splitlines():
            m = re.match(r"^(\s*)([\w.-]+)\s+frames:(\d+)\s+bytes:(\d+)", line)
            if m:
                protos[m.group(2)] = int(m.group(3))
        return protos


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #


def clean_hostname(name: str) -> str:
    """'BLACKJACK<00>|BLACKJACK<00> (Workstation/Redirector)' -> 'BLACKJACK'.
    Los nombres NetBIOS traen sufijo de tipo y a veces vienen repetidos."""
    if not name:
        return ""
    first = name.split("|")[0]
    first = re.sub(r"<[0-9a-fA-F]{2}>?.*$", "", first)
    first = re.sub(r"\s*\(.*\)\s*$", "", first)
    first = first.strip().strip(".")
    # Algunos equipos anuncian marcadores como '--' o 'N/A': no son nombres.
    if not re.search(r"[A-Za-z0-9]", first) or first.lower() in ("n/a", "none", "null"):
        return ""
    return first


def _int_or_none(v: str):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def g(row: list[str], idx: dict[str, int], name: str) -> str:
    i = idx.get(name)
    if i is None or i >= len(row):
        return ""
    return row[i].strip()


def vendor_of(resolved: str, mac: str) -> str:
    """Wireshark resuelve 'RockwellAuto_85:71:4d'; nos quedamos con el fabricante."""
    if not resolved or resolved == mac:
        return ""
    name = resolved.split("_")[0]
    if re.fullmatch(r"[0-9A-Fa-f:.-]+", name):
        return ""
    low = name.lower()
    for key, full in OT_VENDORS.items():
        if low.startswith(key):
            return full
    return name


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_multicast or a.is_link_local or a.is_reserved


def is_apipa(ip: str) -> bool:
    return ip.startswith("169.254.")


def is_unicast_mac(mac: str) -> bool:
    """Descarta multicast y broadcast: el bit I/G es el menos significativo
    del primer octeto. Esas direcciones son grupos de destino, no equipos."""
    if not mac or len(mac) < 2:
        return False
    try:
        return not (int(mac[:2], 16) & 1)
    except ValueError:
        return False


def is_host_ip(ip: str) -> bool:
    """IP que puede pertenecer a un equipo real (no grupo ni comodin)."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255", "::"):
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified)


def port_info(port: str, proto: str) -> tuple[str, str]:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return ("", "")
    return OT_PORTS.get((p, proto), ("", ""))


def human_duration(raw: str) -> str:
    """'2402.100152900 seconds' -> '40 min 2 s'."""
    m = re.search(r"([\d.]+)", raw or "")
    if not m:
        return raw or "?"
    s = float(m.group(1))
    if s < 60:
        return f"{s:.0f} s"
    if s < 3600:
        return f"{int(s // 60)} min {int(s % 60)} s"
    return f"{int(s // 3600)} h {int((s % 3600) // 60)} min"


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# --------------------------------------------------------------------------- #
# Analisis de una captura
# --------------------------------------------------------------------------- #


class Capture:
    def __init__(self, path: Path):
        self.path = path
        self.name = path.name
        self.info: dict = {}
        self.protos: dict[str, int] = {}
        self.sampled = False
        self.flow_packets = 0

        # Activos: clave = MAC
        self.hosts: dict[str, dict] = {}
        # Flujos: (src, dst, dport, proto) -> dict
        self.flows: dict[tuple, dict] = {}
        self.l2_flows: collections.Counter = collections.Counter()
        self.vlans: collections.Counter = collections.Counter()
        self.ethertypes: collections.Counter = collections.Counter()

        # Evidencia del pase de detalle
        self.identity: list[dict] = []
        self.cleartext: list[dict] = []
        self.control_ops: list[dict] = []
        self.arp_events: list[dict] = []
        self.dns_names: collections.Counter = collections.Counter()
        self.stp_tc = 0
        self.icmp_unreach: collections.Counter = collections.Counter()

        self.findings: list[dict] = []

    # -- helpers de inventario -------------------------------------------- #

    def host(self, mac: str, resolved: str = "") -> dict:
        h = self.hosts.get(mac)
        if h is None:
            h = {
                "mac": mac,
                "vendor": vendor_of(resolved, mac),
                "ips": set(),
                "vlans": set(),
                "tx_pkts": 0,
                "rx_pkts": 0,
                "tx_bytes": 0,
                "rx_bytes": 0,
                "proto_seen": collections.Counter(),
                "ports_served": collections.Counter(),
                "ports_used": collections.Counter(),
                "peers": set(),
                "hostnames": set(),
                "fingerprints": set(),
                "first": None,
                "last": None,
            }
            self.hosts[mac] = h
        if not h["vendor"] and resolved:
            h["vendor"] = vendor_of(resolved, mac)
        return h


def analyze_flows(ts: Tshark, cap: Capture, fields: list[str], limit: int) -> None:
    idx = {f: i for i, f in enumerate(fields)}
    n = 0
    for row in ts.fields_pass(cap.path, fields, None, limit):
        n += 1
        esrc = g(row, idx, "eth.src")
        if not esrc:
            continue
        edst = g(row, idx, "eth.dst")
        try:
            blen = int(g(row, idx, "frame.len") or 0)
        except ValueError:
            blen = 0
        try:
            t = float(g(row, idx, "frame.time_epoch") or 0)
        except ValueError:
            t = 0.0

        # Solo las MAC unicast son equipos. ff:ff:... y 01:00:5e:... son grupos
        # de destino y no deben aparecer en el inventario de activos.
        if not is_unicast_mac(esrc):
            continue
        hs = cap.host(esrc, g(row, idx, "eth.src_resolved"))
        hd = (cap.host(edst, g(row, idx, "eth.dst_resolved"))
              if edst and is_unicast_mac(edst) else None)

        hs["tx_pkts"] += 1
        hs["tx_bytes"] += blen
        if hd:
            hd["rx_pkts"] += 1
            hd["rx_bytes"] += blen
        for h in (hs, hd):
            if h is None:
                continue
            if h["first"] is None or (t and t < h["first"]):
                h["first"] = t
            if h["last"] is None or t > h["last"]:
                h["last"] = t

        vlan = g(row, idx, "vlan.id")
        if vlan:
            for v in vlan.split("|"):
                cap.vlans[v] += 1
                hs["vlans"].add(v)
                if hd:
                    hd["vlans"].add(v)

        colproto = g(row, idx, "_ws.col.protocol")
        if colproto:
            hs["proto_seen"][colproto] += 1
            cap.ethertypes[colproto] += 1

        sip = (g(row, idx, "ip.src") or g(row, idx, "ipv6.src")).split("|")[0]
        dip = (g(row, idx, "ip.dst") or g(row, idx, "ipv6.dst")).split("|")[0]
        if is_host_ip(sip):
            hs["ips"].add(sip)
        if hd and is_host_ip(dip):
            hd["ips"].add(dip)

        tsp, tdp = g(row, idx, "tcp.srcport"), g(row, idx, "tcp.dstport")
        usp, udp_ = g(row, idx, "udp.srcport"), g(row, idx, "udp.dstport")
        if tdp:
            l4, sport, dport = "tcp", tsp, tdp
        elif udp_:
            l4, sport, dport = "udp", usp, udp_
        else:
            l4, sport, dport = "", "", ""

        if sip and dip:
            hs["peers"].add(dip)
            if hd:
                hd["peers"].add(sip)
            key = (sip, dip, dport, l4)
            f = cap.flows.get(key)
            if f is None:
                f = {
                    "src": sip, "dst": dip, "dport": dport, "l4": l4,
                    "pkts": 0, "bytes": 0, "proto": colproto,
                    "first": t, "last": t, "sports": set(),
                }
                cap.flows[key] = f
            f["pkts"] += 1
            f["bytes"] += blen
            f["last"] = t
            if sport:
                f["sports"].add(sport)
            if not f["proto"] and colproto:
                f["proto"] = colproto

        # Puertos: el bajo suele ser el que "sirve".
        if l4 and sport and dport:
            try:
                sp, dp = int(sport), int(dport)
            except ValueError:
                sp = dp = 0
            if dp and (dp < sp or dp < 1024 or (dp, l4) in OT_PORTS):
                if hd:
                    hd["ports_served"][(dp, l4)] += 1
                hs["ports_used"][(dp, l4)] += 1
            elif sp:
                hs["ports_served"][(sp, l4)] += 1

        cap.l2_flows[(esrc, edst)] += 1

    cap.flow_packets = n
    cap.sampled = bool(limit) and n >= limit


def analyze_detail(ts: Tshark, cap: Capture, fields: list[str], dfilter: str) -> None:
    idx = {f: i for i, f in enumerate(fields)}

    cip_services = {
        0x01: "Get_Attributes_All",
        0x05: "Reset",
        0x06: "Start",
        0x07: "Stop",
        0x08: "Create",
        0x09: "Delete",
        0x0D: "Apply_Attributes",
        0x0E: "Get_Attribute_Single",
        0x10: "Set_Attribute_Single",
        0x4D: "Write Tag",
        0x4E: "Read Modify Write Tag",
        0x53: "Write Tag Fragmented",
    }
    cip_critical = {0x05, 0x06, 0x07, 0x08, 0x09, 0x0D, 0x10, 0x4D, 0x4E, 0x53}
    modbus_writes = {
        5: "Write Single Coil", 6: "Write Single Register",
        15: "Write Multiple Coils", 16: "Write Multiple Registers",
        22: "Mask Write Register", 23: "Read/Write Multiple Registers",
        8: "Diagnostics", 20: "Read File Record", 21: "Write File Record",
        43: "Encapsulated Interface (Device ID)",
    }
    dnp3_funcs = {
        1: "Read", 2: "Write", 3: "Select", 4: "Operate", 5: "Direct Operate",
        6: "Direct Operate sin respuesta", 7: "Freeze", 13: "Cold Restart",
        14: "Warm Restart", 18: "Stop Application", 20: "Enable Unsolicited",
        21: "Disable Unsolicited", 23: "Delay Measurement", 25: "Open File",
        27: "Delete File", 31: "Activate Config", 32: "Authenticate",
    }
    iec104_types = {
        45: "C_SC_NA_1 comando simple", 46: "C_DC_NA_1 comando doble",
        47: "C_RC_NA_1 comando de regulacion", 48: "C_SE_NA_1 setpoint normalizado",
        49: "C_SE_NB_1 setpoint escalado", 50: "C_SE_NC_1 setpoint flotante",
        51: "C_BO_NA_1 bitstring", 100: "C_IC_NA_1 interrogacion general",
        101: "C_CI_NA_1 interrogacion de contadores", 102: "C_RD_NA_1 lectura",
        103: "C_CS_NA_1 sincronizacion de reloj", 105: "C_RP_NA_1 reset de proceso",
        107: "C_TS_TA_1 prueba",
    }
    s7_funcs = {
        0x04: "Read Var", 0x05: "Write Var", 0x1A: "Request Download",
        0x1B: "Download Block", 0x1C: "Download Ended", 0x1D: "Start Upload",
        0x1E: "Upload", 0x1F: "Upload Ended", 0x28: "PLC Control",
        0x29: "PLC Stop",
    }
    s7_critical = {0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29}

    def add_ident(src_ip, src_mac, kind, value, extra=None):
        if not value:
            return
        cap.identity.append({
            "ip": src_ip, "mac": src_mac, "tipo": kind,
            "valor": value, "detalle": extra or "",
        })
        if src_mac in cap.hosts:
            cap.hosts[src_mac]["fingerprints"].add(f"{kind}: {value}")

    for row in ts.fields_pass(cap.path, fields, dfilter, 0):
        sip = g(row, idx, "ip.src")
        smac = g(row, idx, "eth.src")
        frame = g(row, idx, "frame.number")
        try:
            t = float(g(row, idx, "frame.time_epoch") or 0)
        except ValueError:
            t = 0.0

        def toward_server(port: int) -> bool:
            """Una operacion se cuenta una sola vez: en la peticion. En Modbus,
            DNP3, IEC-104 y S7 la respuesta repite el mismo codigo de funcion,
            asi que nos quedamos con el sentido que va hacia el servidor."""
            return port in (
                _int_or_none(g(row, idx, "tcp.dstport")),
                _int_or_none(g(row, idx, "udp.dstport")),
            )

        # ---- identidad de equipos ---------------------------------------- #
        cdp_dev = g(row, idx, "cdp.deviceid")
        cdp_sw = g(row, idx, "cdp.software_version")
        cdp_pf = g(row, idx, "cdp.platform")
        if cdp_dev or cdp_sw or cdp_pf:
            add_ident(sip, smac, "CDP", f"{cdp_dev} / {cdp_pf}".strip(" /"),
                      cdp_sw.replace("\n", " ")[:400])
            if smac in cap.hosts:
                cap.hosts[smac]["hostnames"].add(cdp_dev)

        lldp_name = g(row, idx, "lldp.tlv.system.name")
        lldp_desc = g(row, idx, "lldp.tlv.system.desc")
        if lldp_name or lldp_desc:
            add_ident(sip, smac, "LLDP", lldp_name or "(sin nombre)",
                      lldp_desc.replace("\n", " ")[:400])
            if smac in cap.hosts and lldp_name and "not set" not in lldp_name.lower():
                cap.hosts[smac]["hostnames"].add(lldp_name)

        srv = g(row, idx, "http.server")
        if srv:
            add_ident(sip, smac, "Banner HTTP", srv)
        ua = g(row, idx, "http.user_agent")
        if ua:
            add_ident(sip, smac, "User-Agent HTTP", ua[:200])
        host_hdr = g(row, idx, "http.host")
        if host_hdr:
            add_ident(sip, smac, "Host HTTP", host_hdr[:120])

        dhcp_host = g(row, idx, "dhcp.option.hostname")
        if dhcp_host:
            add_ident(sip, smac, "Hostname DHCP", dhcp_host)
            if smac in cap.hosts:
                cap.hosts[smac]["hostnames"].add(dhcp_host)
        dhcp_vc = g(row, idx, "dhcp.option.vendor_class_id")
        if dhcp_vc:
            add_ident(sip, smac, "Vendor class DHCP", dhcp_vc)

        nb = g(row, idx, "nbns.name")
        if nb:
            if smac in cap.hosts:
                cap.hosts[smac]["hostnames"].add(nb.strip("<> "))
        brs = g(row, idx, "browser.server")
        if brs:
            add_ident(sip, smac, "SMB Browser", brs)
        nos = g(row, idx, "smb.native_os")
        if nos:
            add_ident(sip, smac, "SMB Native OS", nos)
        sni = g(row, idx, "tls.handshake.extensions_server_name")
        if sni:
            add_ident(sip, smac, "TLS SNI", sni)

        # ---- texto claro / credenciales ---------------------------------- #
        comm = g(row, idx, "snmp.community")
        if comm:
            ver = g(row, idx, "snmp.msgVersion")
            cap.cleartext.append({
                "frame": frame, "ip": sip, "tipo": "SNMP community",
                "detalle": f"community='{comm}' version={ver or '?'}",
            })
        auth = g(row, idx, "http.authorization")
        if auth:
            cap.cleartext.append({
                "frame": frame, "ip": sip, "tipo": "HTTP Authorization",
                "detalle": auth[:120],
            })
        ftpc = g(row, idx, "ftp.request.command")
        if ftpc and ftpc.upper() in ("USER", "PASS"):
            cap.cleartext.append({
                "frame": frame, "ip": sip, "tipo": f"FTP {ftpc.upper()}",
                "detalle": g(row, idx, "ftp.request.arg")[:80],
            })
        tel = g(row, idx, "telnet.data")
        if tel:
            cap.cleartext.append({
                "frame": frame, "ip": sip, "tipo": "Telnet",
                "detalle": tel.replace("\r", " ").replace("\n", " ")[:80],
            })
        for fld, label in (("tftp.source_file", "TFTP lectura"),
                           ("tftp.destination_file", "TFTP escritura")):
            v = g(row, idx, fld)
            if v:
                cap.cleartext.append({
                    "frame": frame, "ip": sip, "tipo": label, "detalle": v[:120],
                })
        ntlm_u = g(row, idx, "ntlmssp.auth.username")
        if ntlm_u and ntlm_u not in ("NULL", ""):
            cap.cleartext.append({
                "frame": frame, "ip": sip, "tipo": "Autenticacion NTLM",
                "detalle": f"{g(row, idx, 'ntlmssp.auth.domain')}\\{ntlm_u}",
            })

        # ---- operaciones de control -------------------------------------- #
        for sv in (g(row, idx, "cip.service") or "").split("|"):
            if not sv:
                continue
            try:
                code = int(sv, 16) if sv.startswith("0x") else int(sv)
            except ValueError:
                continue
            # El bit alto marca respuesta: solo contamos la peticion, si no
            # cada operacion se contaria dos veces.
            if code & 0x80:
                continue
            if code in cip_critical:
                cap.control_ops.append({
                    "frame": frame, "t": t, "proto": "CIP / EtherNet/IP",
                    "src": sip, "dst": g(row, idx, "ip.dst"),
                    "op": cip_services.get(code, f"servicio 0x{code:02x}"),
                    "detalle": g(row, idx, "cip.symbol")[:80],
                })

        for fc in (g(row, idx, "modbus.func_code") or "").split("|"):
            if not fc:
                continue
            try:
                code = int(fc)
            except ValueError:
                continue
            if code in modbus_writes and toward_server(502):
                cap.control_ops.append({
                    "frame": frame, "t": t, "proto": "Modbus/TCP",
                    "src": sip, "dst": g(row, idx, "ip.dst"),
                    "op": f"FC{code} {modbus_writes[code]}",
                    "detalle": f"ref={g(row, idx, 'modbus.reference_num')}",
                })

        for fn in (g(row, idx, "dnp3.al.func") or "").split("|"):
            if not fn:
                continue
            try:
                code = int(fn)
            except ValueError:
                continue
            if code in dnp3_funcs and code != 1 and toward_server(20000):
                cap.control_ops.append({
                    "frame": frame, "t": t, "proto": "DNP3",
                    "src": sip, "dst": g(row, idx, "ip.dst"),
                    "op": f"FC{code} {dnp3_funcs[code]}",
                    "detalle": f"src={g(row, idx, 'dnp3.src')} dst={g(row, idx, 'dnp3.dst')}",
                })

        for ti in (g(row, idx, "iec60870_asdu.typeid") or "").split("|"):
            if not ti:
                continue
            try:
                code = int(ti)
            except ValueError:
                continue
            if code in iec104_types and toward_server(2404):
                cap.control_ops.append({
                    "frame": frame, "t": t, "proto": "IEC 60870-5-104",
                    "src": sip, "dst": g(row, idx, "ip.dst"),
                    "op": f"TypeID {code} {iec104_types[code]}",
                    "detalle": f"causa={g(row, idx, 'iec60870_asdu.causetx')}",
                })

        for sf in (g(row, idx, "s7comm.param.func") or "").split("|"):
            if not sf:
                continue
            try:
                code = int(sf, 16) if sf.startswith("0x") else int(sf)
            except ValueError:
                continue
            if code in s7_critical and toward_server(102):
                cap.control_ops.append({
                    "frame": frame, "t": t, "proto": "S7comm",
                    "src": sip, "dst": g(row, idx, "ip.dst"),
                    "op": s7_funcs.get(code, f"funcion 0x{code:02x}"),
                    "detalle": "",
                })

        mmsreq = g(row, idx, "mms.confirmedServiceRequest")
        if mmsreq:
            cap.control_ops.append({
                "frame": frame, "t": t, "proto": "IEC 61850 MMS",
                "src": sip, "dst": g(row, idx, "ip.dst"),
                "op": f"MMS {mmsreq}", "detalle": "",
            })

        # ---- L2 / anomalias ----------------------------------------------- #
        op = g(row, idx, "arp.opcode")
        if op:
            cap.arp_events.append({
                "frame": frame, "t": t, "opcode": op,
                "hw": g(row, idx, "arp.src.hw_mac"),
                "sip": g(row, idx, "arp.src.proto_ipv4"),
                "dip": g(row, idx, "arp.dst.proto_ipv4"),
                "dup": g(row, idx, "arp.duplicate-address-detected"),
            })
        if g(row, idx, "stp.flags.tc") in ("1", "True"):
            cap.stp_tc += 1
        ic = g(row, idx, "icmp.type")
        if ic == "3":
            cap.icmp_unreach[f"{sip} -> {g(row, idx, 'ip.dst')}"] += 1
        qn = g(row, idx, "dns.qry.name")
        if qn:
            for name in qn.split("|"):
                cap.dns_names[name] += 1


# --------------------------------------------------------------------------- #
# Inferencia de rol y nivel Purdue
# --------------------------------------------------------------------------- #


def infer_roles(cap: Capture) -> None:
    for mac, h in cap.hosts.items():
        protos = {p.lower() for p in h["proto_seen"]}
        served = {p for (p, l4) in h["ports_served"]}
        used = {p for (p, l4) in h["ports_used"]}
        vendor_l = (h["vendor"] or "").lower()
        fps = " ".join(h["fingerprints"]).lower()
        names = " ".join(h["hostnames"]).lower()

        role, why, purdue = "Indeterminado", [], ""

        is_switch = (
            any(s in vendor_l or s in fps or s in names for s in SWITCH_HINTS)
            or "stp" in protos or "cdp" in protos or "gvrp" in protos
        )
        ot_served = served & {502, 20000, 2404, 102, 44818, 4840, 47808, 2222, 18245}
        ot_used = used & {502, 20000, 2404, 102, 44818, 4840, 47808, 18245}
        windows = bool(protos & {"nbns", "browser", "llmnr", "smb", "smb2", "dcerpc", "ssdp"})
        is_ot_vendor = bool(h["vendor"]) and any(
            k in vendor_l for k in ("rockwell", "siemens", "schneider", "abb",
                                    "general electric", "sel", "phoenix", "beckhoff",
                                    "omron", "mitsubishi", "yokogawa", "wago",
                                    "power measurement", "woodward", "prosoft")
        )

        if is_switch:
            role, purdue = "Equipo de red (switch / router)", "Infraestructura"
            why.append("habla STP/CDP/LLDP o el OUI es de un fabricante de switches")
        elif ot_served and not ot_used:
            role, purdue = "Controlador / dispositivo de campo (PLC, RTU, IED)", "Nivel 1"
            why.append(f"atiende puertos OT {sorted(ot_served)}")
        elif ot_used and windows:
            role, purdue = "HMI / estacion SCADA", "Nivel 2"
            why.append(f"consulta puertos OT {sorted(ot_used)} y usa protocolos Windows")
        elif ot_used:
            role, purdue = "Cliente de control (HMI, SCADA o historiador)", "Nivel 2"
            why.append(f"consulta puertos OT {sorted(ot_used)}")
        elif "cip" in protos or "enip" in protos or "cipio" in protos:
            if is_ot_vendor:
                role, purdue = "Dispositivo CIP (controlador o modulo de I/O)", "Nivel 1"
                why.append("trafico EtherNet/IP y OUI de fabricante OT")
            else:
                role, purdue = "Nodo EtherNet/IP", "Nivel 1-2"
                why.append("trafico EtherNet/IP")
        elif windows:
            role, purdue = "Host Windows (estacion de trabajo o servidor)", "Nivel 2-3"
            why.append("protocolos de Windows (SMB/NBNS/LLMNR/SSDP)")
        elif is_ot_vendor:
            role, purdue = f"Dispositivo OT ({h['vendor']})", "Nivel 1-2"
            why.append("OUI de fabricante OT")

        if "ptp" in protos:
            why.append("participa en sincronizacion de tiempo PTP")
        h["role"] = role
        h["purdue"] = purdue
        h["role_why"] = "; ".join(why)


# --------------------------------------------------------------------------- #
# Reglas de hallazgos
# --------------------------------------------------------------------------- #


def finding(cap, sev, titulo, evidencia, porque, recomendacion, categoria="Higiene"):
    cap.findings.append({
        "severidad": sev, "titulo": titulo, "categoria": categoria,
        "evidencia": evidencia, "por_que_importa": porque,
        "recomendacion": recomendacion, "captura": cap.name,
    })


def evaluate(cap: Capture) -> None:
    protos = {p.lower(): c for p, c in cap.ethertypes.items()}
    all_ips = set()
    for h in cap.hosts.values():
        all_ips |= {i for i in h["ips"] if i}

    # --- protocolos de descubrimiento IT en red de control ----------------- #
    noisy = {}
    for name, key in (("LLMNR", "llmnr"), ("NBT-NS", "nbns"), ("mDNS", "mdns"),
                      ("SSDP/UPnP", "ssdp"), ("SMB Browser", "browser")):
        if key in protos:
            noisy[name] = protos[key]
    if noisy:
        finding(
            cap, "Media",
            "Protocolos de descubrimiento de Windows activos en la red de control",
            ", ".join(f"{k}: {v} tramas" for k, v in noisy.items()),
            "LLMNR, NBT-NS y mDNS permiten envenenamiento de resolucion de nombres "
            "(Responder y similares) para capturar hashes NTLM y suplantar servicios. "
            "Un escaner pasivo de corte IT suele reportar esto como vulnerabilidad; "
            "una plataforma OT lo clasifica como higiene y puede no levantar alerta.",
            "Deshabilitar LLMNR y NetBIOS sobre TCP/IP por GPO en los hosts Windows "
            "de la red OT, y bloquear SSDP/mDNS entre VLANs.",
            categoria="Exposicion",
        )

    # --- Sentinel / licenciamiento ----------------------------------------- #
    lic = [f for f in cap.flows.values() if f["dport"] == "1947"]
    if lic:
        srcs = sorted({f["src"] for f in lic})
        finding(
            cap, "Media",
            "Servicio de licenciamiento Sentinel HASP (puerto 1947) en difusion",
            f"{len(lic)} flujos hacia udp/1947 desde {', '.join(srcs[:5])}",
            "El Sentinel LDK/HASP Run-time expone un servicio administrativo web local "
            "y ha acumulado vulnerabilidades criticas (ejecucion remota y denegacion de "
            "servicio). En plantas suele venir embebido con el software de ingenieria y "
            "queda sin parchear. Es un hallazgo tipico de escaneres que miran puertos IT.",
            "Inventariar los hosts con Sentinel, actualizar el runtime al ultimo "
            "release del fabricante y restringir el 1947 a loopback si la licencia es local.",
            categoria="Exposicion",
        )

    # --- texto claro --------------------------------------------------------#
    if cap.cleartext:
        por_tipo = collections.Counter(c["tipo"] for c in cap.cleartext)
        finding(
            cap, "Alta",
            "Credenciales o administracion en texto claro",
            "; ".join(f"{k}: {v}" for k, v in por_tipo.most_common()),
            "Cualquiera con acceso al segmento puede leer credenciales y comandos de "
            "administracion. En OT esto suele ser el camino mas corto de una red de "
            "planta a un controlador.",
            "Migrar a SSH/HTTPS/SNMPv3 donde el equipo lo soporte; donde no, aislar "
            "la administracion en una VLAN dedicada con acceso por jump server.",
            categoria="Exposicion",
        )

    cleartext_ports = collections.Counter()
    for f in cap.flows.values():
        name, cat = port_info(f["dport"], f["l4"])
        if cat == "claro":
            cleartext_ports[name] += f["pkts"]
    if cleartext_ports:
        finding(
            cap, "Media",
            "Protocolos de gestion sin cifrar en uso",
            ", ".join(f"{k}: {v} paquetes" for k, v in cleartext_ports.most_common()),
            "Telnet, FTP, TFTP, HTTP y SNMPv1/v2c transportan credenciales y "
            "configuracion sin proteccion. TFTP ademas se usa para cargar firmware.",
            "Deshabilitar los servicios que no se usen y sustituir los necesarios por "
            "su equivalente cifrado.",
            categoria="Exposicion",
        )

    # --- software obsoleto --------------------------------------------------#
    obsolete = []
    for ident in cap.identity:
        blob = f"{ident['valor']} {ident['detalle']}"
        for pat, label, nota in OBSOLETE_PATTERNS:
            if re.search(pat, blob, re.I):
                obsolete.append((ident.get("ip") or ident.get("mac"), label, nota, blob[:160]))
    if obsolete:
        seen, lines = set(), []
        for ip, label, nota, blob in obsolete:
            k = (ip, label)
            if k in seen:
                continue
            seen.add(k)
            lines.append(f"{ip}: {label} — {nota} | evidencia: {blob}")
        finding(
            cap, "Alta",
            "Software o sistema operativo fuera de soporte",
            "\n".join(f"- {l}" for l in lines),
            "Un sistema sin soporte no recibe parches. Es exactamente el tipo de "
            "hallazgo que un motor de CVE pasivo emite en cuanto logra leer la version.",
            "Levantar plan de reemplazo o compensar con aislamiento de red y control "
            "de acceso estricto mientras se reemplaza.",
            categoria="Obsolescencia",
        )

    # --- firmware visible = material para CVE ------------------------------- #
    fw = [i for i in cap.identity if i["tipo"] in ("CDP", "LLDP") and i["detalle"]]
    if fw:
        finding(
            cap, "Informativa",
            "Version de firmware expuesta en protocolos de descubrimiento",
            "\n".join(f"- {i['valor']}: {i['detalle'][:180]}" for i in fw[:15]),
            "CDP y LLDP anuncian modelo y version de firmware en texto claro. Es la "
            "fuente principal de la que un motor pasivo deriva CVEs. Tambien le sirve "
            "a un atacante con acceso al segmento para elegir exploit sin escanear.",
            "Deshabilitar CDP/LLDP en puertos de acceso que no lo necesiten y "
            "contrastar cada version contra el aviso de seguridad del fabricante "
            "(Cisco PSIRT, Siemens SSA, Rockwell SD).",
            categoria="Identidad",
        )

    # --- direccionamiento ---------------------------------------------------#
    apipa = sorted({i for i in all_ips if is_apipa(i)})
    if apipa:
        finding(
            cap, "Media",
            "Equipos con direccion APIPA (169.254.x.x)",
            ", ".join(apipa[:10]),
            "Una direccion APIPA significa que el equipo no obtuvo IP por DHCP. En "
            "planta suele indicar un dispositivo mal configurado, un servidor DHCP "
            "caido o un equipo conectado donde no debia estar.",
            "Identificar fisicamente cada equipo y corregir su direccionamiento; "
            "si no debe estar en la red, retirarlo.",
            categoria="Configuracion",
        )

    publics = sorted({i for i in all_ips if i and ":" not in i and not is_private(i)})
    if publics:
        finding(
            cap, "Alta",
            "Trafico con direcciones IP publicas desde la red OT",
            ", ".join(publics[:15]),
            "Comunicacion hacia Internet desde un segmento de control rompe la "
            "segmentacion esperada y es via de exfiltracion y de mando y control.",
            "Verificar si son equipos de planta o trafico de transito mal segmentado; "
            "bloquear la salida directa a Internet desde niveles 0-2.",
            categoria="Segmentacion",
        )

    # subredes: muchas /24 distintas en un mismo dominio de difusion
    subnets = collections.Counter()
    for i in all_ips:
        if i and ":" not in i and not is_apipa(i):
            subnets[".".join(i.split(".")[:3])] += 1
    if len(subnets) > 3:
        finding(
            cap, "Media",
            "Multiples subredes conviviendo en el mismo dominio de difusion",
            ", ".join(f"{k}.0/24 ({v} hosts)" for k, v in subnets.most_common(10)),
            "Varias subredes en el mismo segmento L2 indican segmentacion incompleta: "
            "el aislamiento logico no esta respaldado por aislamiento de red.",
            "Revisar el diseno de VLANs y el plan de direccionamiento contra el "
            "modelo de zonas y conductos (IEC 62443).",
            categoria="Segmentacion",
        )

    if len(cap.vlans) <= 1 and cap.flow_packets > 1000:
        finding(
            cap, "Informativa",
            "Sin segmentacion por VLAN visible en el punto de captura",
            f"VLANs observadas: {', '.join(cap.vlans) or 'ninguna (tramas sin etiqueta 802.1Q)'}",
            "Puede ser que no haya VLANs, o que el puerto SPAN entregue las tramas "
            "sin etiqueta. Lo segundo le quita contexto a cualquier sensor pasivo.",
            "Confirmar con el equipo de redes si el SPAN preserva el tag 802.1Q.",
            categoria="Visibilidad",
        )

    # --- RIP / protocolos de ruteo sin autenticacion ------------------------ #
    if "rip" in protos:
        finding(
            cap, "Media",
            "RIP activo en la red de control",
            f"{protos['rip']} tramas RIP",
            "RIP sin autenticacion permite inyectar rutas falsas y desviar trafico. "
            "Ademas es un protocolo que no suele tener razon de existir en un "
            "segmento de control moderno.",
            "Eliminar RIP o, si se requiere ruteo dinamico, migrar a OSPF con "
            "autenticacion y filtrado de vecinos.",
            categoria="Configuracion",
        )

    # --- DHCP en red de control --------------------------------------------#
    if "dhcp" in protos and protos["dhcp"] > 5:
        finding(
            cap, "Baja",
            "DHCP activo en el segmento de control",
            f"{protos['dhcp']} tramas DHCP",
            "El direccionamiento dinamico en nivel 1-2 complica el inventario, "
            "rompe reglas de firewall basadas en IP y dificulta la trazabilidad.",
            "Usar direccionamiento estatico o reservas por MAC para dispositivos de control.",
            categoria="Configuracion",
        )

    # --- ARP ----------------------------------------------------------------#
    ip2mac = collections.defaultdict(set)
    mac2ip = collections.defaultdict(set)
    for e in cap.arp_events:
        # Un ARP probe anuncia 0.0.0.0 como origen: no es un duplicado de IP.
        if is_host_ip(e["sip"]) and is_unicast_mac(e["hw"]):
            ip2mac[e["sip"]].add(e["hw"])
            mac2ip[e["hw"]].add(e["sip"])
    conflicts = {ip: macs for ip, macs in ip2mac.items() if len(macs) > 1}
    if conflicts:
        finding(
            cap, "Alta",
            "Conflicto de direcciones: una misma IP anunciada por varias MAC",
            "\n".join(f"- {ip}: {', '.join(sorted(m))}" for ip, m in list(conflicts.items())[:10]),
            "Puede ser un duplicado de IP por error de configuracion o un intento de "
            "ARP spoofing. En una red de control, un ARP spoofing exitoso permite "
            "interceptar o alterar comandos entre HMI y controlador.",
            "Identificar los equipos por puerto de switch, corregir duplicados y "
            "habilitar Dynamic ARP Inspection y DHCP snooping donde el switch lo soporte.",
            categoria="Anomalia",
        )

    dup_flag = [e for e in cap.arp_events if e["dup"]]
    if dup_flag:
        finding(
            cap, "Alta",
            "Wireshark marco deteccion de direccion duplicada en ARP",
            f"{len(dup_flag)} eventos; primero en la trama {dup_flag[0]['frame']}",
            "Confirma el punto anterior con la propia deteccion del disector.",
            "Resolver el duplicado antes de cualquier otra accion: provoca perdida "
            "intermitente de comunicacion con el equipo afectado.",
            categoria="Anomalia",
        )

    # escaneo ARP: un host preguntando por muchas IPs
    asker = collections.Counter()
    for e in cap.arp_events:
        if e["opcode"] == "1" and e["dip"]:
            asker[e["hw"]] += 1
    targets = collections.defaultdict(set)
    for e in cap.arp_events:
        if e["opcode"] == "1" and e["dip"] and e["hw"]:
            targets[e["hw"]].add(e["dip"])
    sweepers = {m: t for m, t in targets.items() if len(t) >= 25}
    if sweepers:
        finding(
            cap, "Media",
            "Barrido ARP: un equipo pregunta por muchas direcciones",
            "\n".join(f"- {m} ({cap.hosts.get(m, {}).get('vendor', '?')}): "
                      f"{len(t)} IPs distintas" for m, t in list(sweepers.items())[:8]),
            "Puede ser una herramienta de descubrimiento legitima (inventario, el "
            "propio escaner del cliente) o reconocimiento no autorizado. Conviene "
            "atribuirlo antes de descartarlo.",
            "Confirmar con el cliente si corresponde a una herramienta autorizada y "
            "en que ventana se ejecuto.",
            categoria="Anomalia",
        )

    # --- escaneo de puertos / hosts ----------------------------------------#
    scan_ports = collections.defaultdict(set)
    scan_hosts = collections.defaultdict(set)
    for f in cap.flows.values():
        if f["dport"] and is_host_ip(f["src"]) and is_host_ip(f["dst"]):
            scan_ports[f["src"]].add((f["dst"], f["dport"]))
            scan_hosts[f["src"]].add(f["dst"])
    port_scanners = {s: v for s, v in scan_ports.items() if len(v) >= 50}
    host_scanners = {s: v for s, v in scan_hosts.items() if len(v) >= 25}
    if port_scanners or host_scanners:
        lines = []
        for s, v in list(port_scanners.items())[:5]:
            lines.append(f"- {s}: {len(v)} pares destino/puerto distintos")
        for s, v in list(host_scanners.items())[:5]:
            lines.append(f"- {s}: contacto con {len(v)} destinos distintos")
        finding(
            cap, "Media",
            "Patron compatible con escaneo de red",
            "\n".join(lines),
            "El escaneo activo en redes OT puede tumbar dispositivos de campo que no "
            "toleran trafico inesperado. Si es el escaner del cliente, explica tambien "
            "por que esa herramienta genera hallazgos que un sensor pasivo no produce.",
            "Atribuir el origen. Si es una herramienta autorizada, documentar la "
            "ventana y evaluar el riesgo de escaneo activo sobre nivel 1.",
            categoria="Anomalia",
        )

    # --- storms -------------------------------------------------------------#
    bcast = sum(c for (s, d), c in cap.l2_flows.items() if d == "ff:ff:ff:ff:ff:ff")
    if cap.flow_packets and bcast / cap.flow_packets > 0.20:
        finding(
            cap, "Media",
            "Proporcion alta de trafico de difusion",
            f"{bcast} de {cap.flow_packets} paquetes ({bcast / cap.flow_packets:.0%}) son broadcast",
            "Un exceso de difusion degrada el desempeno de los dispositivos de campo, "
            "que tienen pilas de red limitadas, y puede causar perdida de comunicacion.",
            "Revisar storm control en los switches y reducir el tamano del dominio de difusion.",
            categoria="Desempeno",
        )

    if cap.stp_tc > 20:
        finding(
            cap, "Media",
            "Cambios de topologia STP frecuentes",
            f"{cap.stp_tc} notificaciones de cambio de topologia (TCN)",
            "Un STP inestable provoca microcortes. En control, un microcorte puede "
            "derivar en perdida de comunicacion con un controlador y en un disparo.",
            "Identificar el puerto que genera los TCN y habilitar PortFast/Edge Port "
            "y BPDU Guard en los puertos de dispositivos finales.",
            categoria="Desempeno",
        )

    # --- operaciones de control --------------------------------------------#
    if cap.control_ops:
        por_op = collections.Counter(f"{c['proto']}: {c['op']}" for c in cap.control_ops)
        pares = collections.Counter(f"{c['src']} -> {c['dst']}" for c in cap.control_ops)
        finding(
            cap, "Alta",
            "Operaciones de escritura o control observadas en la captura",
            "Operaciones: " + "; ".join(f"{k} ({v})" for k, v in por_op.most_common(10))
            + "\nPares: " + "; ".join(f"{k} ({v})" for k, v in pares.most_common(5)),
            "Estas son escrituras y comandos reales sobre el proceso, no lecturas. "
            "Hay que confirmar que cada origen esta autorizado a escribir sobre ese "
            "destino: es el control mas importante del nivel 1.",
            "Validar la lista de origenes autorizados a escribir y restringir la "
            "escritura por firewall OT o por configuracion del controlador.",
            categoria="Control",
        )
    else:
        finding(
            cap, "Informativa",
            "No se observaron escrituras ni comandos de control",
            "Solo trafico de lectura o de I/O ciclico en el periodo capturado.",
            "La captura refleja operacion en estado estable. No permite concluir que "
            "no existan escrituras: solo que no ocurrieron en esta ventana.",
            "Para evaluar control de escritura hace falta capturar durante una "
            "maniobra o una sesion de ingenieria.",
            categoria="Control",
        )

    # --- programacion / ingenieria ------------------------------------------#
    eng = [c for c in cap.control_ops
           if any(k in c["op"] for k in ("Download", "Upload", "Stop", "Start",
                                         "Reset", "PLC Control", "Apply"))]
    if eng:
        finding(
            cap, "Alta",
            "Actividad de ingenieria sobre controladores (descarga, arranque o paro)",
            "; ".join(f"{c['src']} -> {c['dst']}: {c['op']} (trama {c['frame']})"
                      for c in eng[:10]),
            "Descargar logica, detener o arrancar un controlador son las operaciones "
            "de mayor impacto en una planta. Deben venir solo de estaciones de "
            "ingenieria identificadas y en ventana autorizada.",
            "Correlacionar con la bitacora de cambios del cliente. Si no hay registro "
            "que lo respalde, tratarlo como incidente.",
            categoria="Control",
        )


def evaluate_visibility(cap: Capture) -> None:
    """Por que un sensor pasivo podria no ver lo que si esta en la captura."""
    info = cap.info

    # 1. Truncamiento
    snap = info.get("Packet size limit") or info.get("Packet size limit (min/max)") or ""
    m = re.search(r"(\d+)", snap)
    if m and int(m.group(1)) and int(m.group(1)) < 1500:
        finding(
            cap, "Alta",
            "Captura truncada (snaplen por debajo del MTU)",
            f"Limite de tamano de paquete: {snap}",
            "Con los paquetes cortados, el disector no alcanza a leer banners, "
            "versiones de firmware ni contenido de protocolo. Un motor de CVE pasivo "
            "se queda sin la evidencia que necesita y no emite hallazgos. Esta es una "
            "causa frecuente de 'la herramienta no ve nada'.",
            "Recapturar con snaplen completo (sin -s) para el analisis de identidad.",
            categoria="Visibilidad",
        )

    # 2. Trafico unidireccional: SPAN configurado solo en una direccion
    # Solo cuentan los pares unicast: el multicast y el broadcast son
    # unidireccionales por diseno y dirian que el SPAN esta mal sin estarlo.
    pairs: dict[tuple, set] = {}
    for (src, dst, dport, l4), f in cap.flows.items():
        if not is_host_ip(src) or not is_host_ip(dst):
            continue
        key = tuple(sorted((src, dst)))
        pairs.setdefault(key, set()).add((src, dst))
    oneway = [k for k, v in pairs.items() if len(v) == 1]
    if pairs and len(oneway) / len(pairs) > 0.6 and len(pairs) >= 5:
        finding(
            cap, "Alta",
            "La mayoria de las conversaciones aparece en un solo sentido",
            f"{len(oneway)} de {len(pairs)} pares de IPs sin trafico de vuelta",
            "Un SPAN configurado solo en RX (o solo en TX), o un TAP de una sola fibra, "
            "entrega media conversacion. El sensor no puede correlacionar peticion y "
            "respuesta, y pierde justo las respuestas, que son las que traen banners, "
            "identidad y version de firmware. Explica directamente que una herramienta "
            "con otro punto de captura si encuentre hallazgos.",
            "Reconfigurar el SPAN como 'both' o instalar un TAP que agregue ambas "
            "direcciones, y validar con un conteo de paquetes por sentido.",
            categoria="Visibilidad",
        )

    # 2b. Casi nada de unicast: el sensor solo ve lo que se inunda
    l2_total = sum(cap.l2_flows.values())
    l2_uni = sum(n for (s, d), n in cap.l2_flows.items() if is_unicast_mac(d))
    if l2_total > 2000 and l2_uni / l2_total < 0.15:
        finding(
            cap, "Alta",
            "El punto de captura casi no ve trafico unicast",
            f"Solo {l2_uni} de {l2_total} paquetes ({l2_uni / l2_total:.1%}) "
            f"van a una MAC unicast; el resto es difusion o multicast.",
            "Un puerto que solo recibe lo que el switch inunda (difusion, "
            "multicast y trafico desconocido) no ve las conversaciones "
            "cliente-servidor. Ahi es justo donde viven la mensajeria explicita, "
            "los banners y las negociaciones que permiten identificar modelo y "
            "firmware. Un sensor conectado en este punto construye un inventario "
            "parcial y no puede enumerar vulnerabilidades, mientras que otro "
            "conectado donde si pasa el unicast si lo logra. Es de las "
            "explicaciones mas frecuentes de que dos herramientas no coincidan.",
            "Verificar que el SPAN tenga como fuente los puertos o la VLAN "
            "completa de los equipos de interes, no solo un puerto de acceso, "
            "y que este configurado en ambos sentidos.",
            categoria="Visibilidad",
        )

    # 3. Paquetes de identidad: cuantos hay realmente
    ident_frames = len(cap.identity)
    total = cap.flow_packets or 1
    if ident_frames == 0:
        finding(
            cap, "Alta",
            "La captura no contiene ningun paquete que revele identidad de equipos",
            "Sin CDP, LLDP, banners, respuestas de descubrimiento ni objetos de identidad.",
            "Un sensor pasivo deriva fabricante, modelo y firmware de estos paquetes. "
            "Sin ellos no puede hacer match contra su base de CVEs, y por eso reporta "
            "cero vulnerabilidades aunque los equipos si sean vulnerables. La ausencia "
            "de hallazgos aqui es ausencia de evidencia, no evidencia de ausencia.",
            "Capturar durante un arranque de equipo o una sesion de ingenieria, o "
            "habilitar sondeo activo (Smart Polling o equivalente) en el sensor.",
            categoria="Visibilidad",
        )
    elif ident_frames < 50:
        finding(
            cap, "Media",
            "Muy pocos paquetes de identidad en la captura",
            f"{ident_frames} paquetes con informacion de identidad sobre "
            f"{total} analizados ({ident_frames / total:.4%})",
            "Los paquetes que permiten identificar un equipo son escasos y "
            "esporadicos (anuncios cada 30-60 s, respuestas de descubrimiento, "
            "negociaciones iniciales). Una ventana de captura corta, o un sensor que "
            "arranco despues de que los equipos ya habian negociado, se los pierde.",
            "Extender la ventana de captura a varias horas y cubrir un arranque de "
            "sistema, o complementar con sondeo activo controlado.",
            categoria="Visibilidad",
        )

    # 4. I/O ciclico dominante: trafico que no fingerprintea
    # Nombres tal como los escribe la columna "Protocol" de Wireshark.
    # Solo el I/O ciclico: la mensajeria explicita (CIP sobre TCP, MMS) si
    # puede revelar identidad y no debe contarse aqui.
    cyclic_markers = ("cip i/o", "cipio", "profinet", "pn-io", "pnio",
                      "goose", "sampled value", "iec61850 sv")
    cyclic = sum(c for p, c in cap.ethertypes.items()
                 if any(m in p.lower() for m in cyclic_markers))
    if cyclic and cyclic / total > 0.7:
        finding(
            cap, "Informativa",
            "El trafico es casi todo I/O ciclico, que no revela identidad",
            f"{cyclic} de {total} paquetes ({cyclic / total:.0%}) son I/O ciclico "
            f"(CIP Class 1 / PROFINET RT / GOOSE / SV)",
            "El I/O ciclico lleva solo valores de proceso: ni modelo, ni version, ni "
            "comandos. Un sensor pasivo lo usa para construir el mapa de "
            "comunicaciones y la linea base, pero no para enumerar vulnerabilidades. "
            "Es la razon tecnica mas probable de que la plataforma OT muestre los "
            "activos pero sin CVEs asociados.",
            "Para enumerar vulnerabilidades hace falta mensajeria explicita "
            "(ENIP/CIP sobre TCP 44818, MMS, lecturas de objeto Identity) o sondeo activo.",
            categoria="Visibilidad",
        )

    # 5. Duplicados por SPAN mal armado
    dups = info.get("Number of duplicate packets") or ""
    if dups and re.search(r"[1-9]", dups):
        finding(
            cap, "Baja",
            "Paquetes duplicados en la captura",
            f"Duplicados reportados: {dups}",
            "Un SPAN que copia el mismo paquete desde varios puertos infla los "
            "conteos y puede disparar falsos positivos de retransmision en el sensor.",
            "Ajustar la fuente del SPAN para no duplicar.",
            categoria="Visibilidad",
        )

    # 6. Ventana de captura corta
    dur = info.get("Capture duration") or ""
    md = re.search(r"([\d.]+)\s*seconds", dur)
    if md and float(md.group(1)) < 900:
        finding(
            cap, "Media",
            "Ventana de captura corta",
            f"Duracion: {dur}",
            "Menos de 15 minutos no alcanza a cubrir ciclos lentos: anuncios LLDP/CDP, "
            "polling de historiador, respaldos, sincronizaciones y sesiones de "
            "ingenieria. Dos herramientas comparadas sobre ventanas distintas no son "
            "comparables.",
            "Para el assessment, capturar al menos 24 h en cada punto, o acordar la "
            "misma ventana para ambas herramientas.",
            categoria="Visibilidad",
        )


# --------------------------------------------------------------------------- #
# Reporte
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Consolidacion entre capturas: inventario unico y matriz de comunicaciones
# --------------------------------------------------------------------------- #

FW_PATTERNS = [
    r"FW:\s*Version\s*([\w.\-]+)",
    r"\bFW[:\s]+([\w.\-]{3,})",
    r"SW:\s*([\w.\-]+)",
    r"\bVersion\s+(\d[\w.()\-]*)",
    r"\bv(\d+\.\d+\.\d+[\w.\-]*)",
]


def extract_fw(text: str) -> str:
    for pat in FW_PATTERNS:
        m = re.search(pat, text or "")
        if m:
            return m.group(1).rstrip(",;")
    return ""


def merge_assets(caps: list[Capture]) -> tuple[dict, dict]:
    """Une los activos de todas las capturas por MAC y devuelve
    (inventario, indice IP -> activo). Un mismo equipo visto desde varios
    puntos de captura es un solo renglon del inventario."""
    assets: dict[str, dict] = {}
    for c in caps:
        for mac, h in c.hosts.items():
            a = assets.get(mac)
            if a is None:
                a = {
                    "mac": mac, "vendor": h["vendor"], "ips": set(), "vlans": set(),
                    "hostnames": set(), "protos": collections.Counter(),
                    "ports_served": collections.Counter(), "pkts": 0, "bytes": 0,
                    "capturas": set(), "identidad": [], "role": "", "purdue": "",
                    "role_why": "", "_role_weight": -1,
                }
                assets[mac] = a
            a["ips"] |= h["ips"]
            a["vlans"] |= h["vlans"]
            a["hostnames"] |= {
                c2 for c2 in (clean_hostname(n) for n in h["hostnames"])
                if c2 and "not set" not in c2.lower()
            }
            a["protos"].update(h["proto_seen"])
            a["ports_served"].update(h["ports_served"])
            a["pkts"] += h["tx_pkts"] + h["rx_pkts"]
            a["bytes"] += h["tx_bytes"] + h["rx_bytes"]
            a["capturas"].add(c.name)
            if not a["vendor"] and h["vendor"]:
                a["vendor"] = h["vendor"]
            # El rol se toma de la captura donde mas se vio al equipo.
            w = h["tx_pkts"] + h["rx_pkts"]
            if h.get("role") and h["role"] != "Indeterminado" and w > a["_role_weight"]:
                a["role"] = h["role"]
                a["purdue"] = h.get("purdue", "")
                a["role_why"] = h.get("role_why", "")
                a["_role_weight"] = w

    for c in caps:
        for i in c.identity:
            a = assets.get(i["mac"])
            if a is not None:
                a["identidad"].append(i)

    # Modelo y firmware a partir de los anuncios de descubrimiento.
    for a in assets.values():
        modelo, firmware = "", ""
        for i in a["identidad"]:
            blob = f"{i['valor']} {i['detalle']}"
            if i["tipo"] == "CDP" and not modelo:
                # El valor viene como "<deviceid> / <plataforma>"; nos quedamos
                # con la plataforma, que es el modelo real del equipo.
                partes = i["valor"].split(" / ", 1)
                modelo = (partes[1] if len(partes) > 1 else partes[0])
                # El campo puede traer varias ocurrencias unidas por '|'.
                modelo = modelo.split("|")[0].strip()
            if i["tipo"] == "LLDP" and not modelo and i["detalle"]:
                modelo = i["detalle"][:70]
            if i["tipo"] in ("Banner HTTP", "SMB Native OS") and not modelo:
                modelo = i["valor"][:70]
            if not firmware:
                firmware = extract_fw(blob)
        a["modelo"] = modelo
        a["firmware"] = firmware
        a["nombre"] = (sorted(a["hostnames"])[0] if a["hostnames"]
                       else (sorted(a["ips"])[0] if a["ips"] else a["mac"]))
        a.pop("_role_weight", None)

    ip_index: dict[str, dict] = {}
    for a in assets.values():
        for ip in a["ips"]:
            # Si dos equipos reclaman la misma IP se queda el de mas trafico;
            # el conflicto ya se reporta como hallazgo aparte.
            if ip not in ip_index or a["pkts"] > ip_index[ip]["pkts"]:
                ip_index[ip] = a
    return assets, ip_index


def build_conduits(caps: list[Capture], ip_index: dict) -> list[dict]:
    """Matriz de comunicaciones: un renglon por relacion origen -> destino -> servicio."""
    pairs: set[tuple[str, str]] = set()
    for c in caps:
        for f in c.flows.values():
            if f["src"] and f["dst"]:
                pairs.add((f["src"], f["dst"]))

    # Escrituras y comandos por par, para marcar los conductos de control.
    writes: collections.Counter = collections.Counter()
    for c in caps:
        for o in c.control_ops:
            writes[(o["src"], o["dst"])] += 1

    conduits: dict[tuple, dict] = {}
    for c in caps:
        for f in c.flows.values():
            src, dst = f["src"], f["dst"]
            if not src or not dst or not is_host_ip(src):
                continue
            svc, cat = port_info(f["dport"], f["l4"])
            key = (src, dst, f["l4"], f["dport"])
            k = conduits.get(key)
            if k is None:
                a_src = ip_index.get(src, {})
                a_dst = ip_index.get(dst, {})
                try:
                    dst_mc = ipaddress.ip_address(dst).is_multicast
                except ValueError:
                    dst_mc = False
                k = {
                    "src": src, "dst": dst, "l4": f["l4"], "port": f["dport"],
                    "servicio": svc or f["proto"] or "-",
                    "categoria": cat or ("multicast" if dst_mc else "otro"),
                    "src_nombre": a_src.get("nombre", src),
                    "dst_nombre": (a_dst.get("nombre") or
                                   ("grupo multicast" if dst_mc else dst)),
                    "src_rol": a_src.get("role", ""), "dst_rol": a_dst.get("role", ""),
                    "src_zona": a_src.get("purdue", ""), "dst_zona": a_dst.get("purdue", ""),
                    "pkts": 0, "bytes": 0, "capturas": set(),
                    "multicast": dst_mc,
                }
                conduits[key] = k
            k["pkts"] += f["pkts"]
            k["bytes"] += f["bytes"]
            k["capturas"].add(c.name)

    out = []
    for k in conduits.values():
        k["bidireccional"] = (k["dst"], k["src"]) in pairs
        k["escrituras"] = writes.get((k["src"], k["dst"]), 0)
        zs, zd = k["src_zona"], k["dst_zona"]
        k["cruza_zona"] = bool(zs and zd and zs != zd and not k["multicast"])
        if k["escrituras"]:
            k["criticidad"] = "Critica"
        elif k["categoria"] == "ot" and k["cruza_zona"]:
            k["criticidad"] = "Alta"
        elif k["categoria"] == "ot":
            k["criticidad"] = "Media"
        elif k["categoria"] == "claro":
            k["criticidad"] = "Media"
        elif k["cruza_zona"]:
            k["criticidad"] = "Media"
        else:
            k["criticidad"] = "Baja"
        out.append(k)
    out.sort(key=lambda x: (CRIT_ORDER.get(x["criticidad"], 9), -x["pkts"]))
    return out


CRIT_ORDER = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3}


def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def strip_tags(s: str) -> str:
    """<strong>x</strong> -> **x**, para reutilizar los textos en Markdown."""
    s = re.sub(r"</?strong>", "**", s or "")
    return re.sub(r"<[^>]+>", "", s)


def write_report(caps: list[Capture], assets: dict, conduits: list[dict],
                 outdir: Path, args) -> Path:
    out = []
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    out.append("# Reporte de assessment OT sobre capturas de red\n")
    out.append(f"_Generado el {now} con `ot_pcap_assess.py`._\n")

    # --- resumen -------------------------------------------------------- #
    total_pkts = sum(c.flow_packets for c in caps)
    all_hosts = {}
    for c in caps:
        for mac, h in c.hosts.items():
            all_hosts.setdefault(mac, h)
    all_findings = [f for c in caps for f in c.findings]
    by_sev = collections.Counter(f["severidad"] for f in all_findings)

    out.append("## 1. Resumen\n")
    out.append(f"- Capturas analizadas: **{len(caps)}**")
    out.append(f"- Paquetes procesados: **{total_pkts:,}**")
    out.append(f"- Equipos distintos (por MAC): **{len(all_hosts)}**")
    out.append(f"- Hallazgos: " + ", ".join(
        f"**{by_sev.get(s, 0)}** {s.lower()}" for s in ("Alta", "Media", "Baja", "Informativa")
    ))
    if any(c.sampled for c in caps):
        out.append(
            f"\n> Nota: una o mas capturas se analizaron sobre una muestra de "
            f"{args.max_packets:,} paquetes para el mapa de flujos. Los conteos de "
            f"protocolo vienen del archivo completo. Use `--max-packets 0` para "
            f"procesar todo."
        )
    out.append("")

    # --- hallazgos ------------------------------------------------------ #
    out.append("## 2. Hallazgos\n")
    # Se agrupan hallazgos iguales que aparecen en varias capturas.
    grouped: dict[tuple, dict] = {}
    for f in all_findings:
        k = (f["titulo"], f["severidad"])
        if k in grouped:
            grouped[k]["capturas"].append(f["captura"])
            grouped[k]["evidencia"] += f"\n\n_({f['captura']})_ " + f["evidencia"]
        else:
            g_ = dict(f)
            g_["capturas"] = [f["captura"]]
            g_["evidencia"] = f"_({f['captura']})_ " + f["evidencia"]
            grouped[k] = g_
    ordered = sorted(grouped.values(),
                     key=lambda f: (SEV_ORDER.get(f["severidad"], 9), f["titulo"]))

    out.append("| # | Severidad | Categoria | Hallazgo | Capturas |")
    out.append("|---|---|---|---|---|")
    for i, f in enumerate(ordered, 1):
        out.append(f"| {i} | {f['severidad']} | {f['categoria']} | "
                   f"{md_escape(f['titulo'])} | {len(f['capturas'])} |")
    out.append("")

    for i, f in enumerate(ordered, 1):
        out.append(f"### {i}. [{f['severidad']}] {f['titulo']}\n")
        out.append(f"**Categoria:** {f['categoria']}  ")
        out.append(f"**Capturas:** {', '.join(sorted(set(f['capturas'])))}\n")
        out.append("**Evidencia**\n")
        out.append("```")
        out.append(f["evidencia"])
        out.append("```\n")
        out.append(f"**Por que importa.** {f['por_que_importa']}\n")
        out.append(f"**Recomendacion.** {f['recomendacion']}\n")

    # --- inventario ----------------------------------------------------- #
    out.append("## 3. Inventario de activos\n")
    out.append("Consolidado entre todos los puntos de captura. Rol y zona son "
               "inferidos del comportamiento observado, no declarados por el "
               "equipo: hay que validarlos con el personal de planta.\n")
    out.append("| # | Equipo | IP | MAC | Fabricante | Modelo / descripcion | "
               "Firmware | Rol inferido | Zona | VLAN | Paquetes |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|")
    rows = sorted(assets.values(), key=lambda x: (-x["pkts"], x["mac"]))
    for i, ast in enumerate(rows[: args.max_rows], 1):
        out.append(
            f"| {i} | {md_escape(ast['nombre'])} "
            f"| {md_escape(', '.join(sorted(ast['ips'])[:3]) or '-')} "
            f"| `{ast['mac']}` | {md_escape(ast['vendor'] or '-')} "
            f"| {md_escape(ast.get('modelo') or '-')} "
            f"| {md_escape(ast.get('firmware') or '-')} "
            f"| {md_escape(ast['role'] or 'Indeterminado')} "
            f"| {ast['purdue'] or '-'} "
            f"| {', '.join(sorted(ast['vlans'])) or '-'} | {ast['pkts']:,} |"
        )
    if len(rows) > args.max_rows:
        out.append(f"\n_({len(rows) - args.max_rows} equipos mas en `inventario.csv`.)_")
    con_fw = [x for x in rows if x.get("firmware")]
    out.append(f"\n**{len(con_fw)} de {len(rows)}** activos revelaron version de "
               f"firmware de forma pasiva. Solo sobre esos puede un motor de "
               f"vulnerabilidades hacer correspondencia con su base de CVEs.\n")

    # --- matriz de comunicaciones --------------------------------------- #
    out.append("## 4. Matriz de comunicaciones\n")
    out.append("Cada renglon es una relacion origen -> destino -> servicio. La "
               "criticidad combina el tipo de servicio, si cruza zonas y si "
               "transporta operaciones de escritura al proceso.\n")
    out.append("| # | Origen | Zona | Destino | Zona | Servicio | Puerto | "
               "Sentido | Paquetes | Volumen | Escrituras | Criticidad |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for i, k in enumerate(conduits[: args.max_rows], 1):
        out.append(
            f"| {i} | {md_escape(k['src_nombre'])} ({k['src']}) "
            f"| {k['src_zona'] or '-'}{' **>**' if k['cruza_zona'] else ''} "
            f"| {md_escape(k['dst_nombre'])} ({k['dst']}) | {k['dst_zona'] or '-'} "
            f"| {md_escape(k['servicio'])} | {k['l4']}/{k['port'] or '-'} "
            f"| {'bidireccional' if k['bidireccional'] else 'unidireccional'} "
            f"| {k['pkts']:,} | {human(k['bytes'])} "
            f"| {k['escrituras'] or '-'} | {k['criticidad']} |"
        )
    if len(conduits) > args.max_rows:
        out.append(f"\n_({len(conduits) - args.max_rows} conductos mas en "
                   f"`comunicaciones.csv`.)_")
    cross = [k for k in conduits if k["cruza_zona"]]
    if cross:
        out.append(f"\n**{len(cross)} conductos cruzan zonas.** Son los candidatos "
                   f"naturales a control por firewall OT bajo el modelo de zonas "
                   f"y conductos de IEC 62443.\n")
    out.append("")

    # --- identidad ------------------------------------------------------ #
    out.append("## 5. Identidad de equipos observada (insumo para CVEs)\n")
    out.append("Esto es lo que un motor pasivo de vulnerabilidades usa para hacer "
               "match contra su base. Si esta tabla sale vacia o corta, la herramienta "
               "no tiene con que trabajar.\n")
    idents = [i for c in caps for i in c.identity]
    seen = set()
    uniq = []
    for i in idents:
        k = (i["tipo"], i["valor"], i["detalle"][:80])
        if k not in seen:
            seen.add(k)
            uniq.append(i)
    if uniq:
        out.append("| Origen | Tipo | Valor | Detalle |")
        out.append("|---|---|---|---|")
        for i in uniq[: args.max_rows]:
            out.append(f"| {i['ip'] or i['mac']} | {i['tipo']} | "
                       f"{md_escape(i['valor'][:60])} | {md_escape(i['detalle'][:160])} |")
        if len(uniq) > args.max_rows:
            out.append(f"\n_({len(uniq) - args.max_rows} mas en `identidad.csv`.)_")
    else:
        out.append("_No se observo ningun paquete con informacion de identidad._")
    out.append("")

    # --- protocolos ----------------------------------------------------- #
    out.append("## 6. Detalle por captura\n")
    for c in caps:
        out.append(f"### {c.name}\n")
        info = c.info
        meta = []
        for k in ("Number of packets", "Capture duration", "First packet time",
                  "Last packet time", "Packet size limit", "Data byte rate",
                  "Number of duplicate packets"):
            if info.get(k):
                meta.append(f"- **{k}**: {info[k]}")
        out.append("\n".join(meta) + "\n")

        top = sorted(c.protos.items(), key=lambda kv: -kv[1])[:18]
        if top:
            out.append("| Protocolo | Tramas |")
            out.append("|---|---|")
            for p, n in top:
                out.append(f"| {p} | {n:,} |")
            out.append("")

        flows = sorted(c.flows.values(), key=lambda f: -f["pkts"])[:20]
        if flows:
            out.append("**Flujos principales**\n")
            out.append("| Origen | Destino | Puerto | Servicio | Protocolo | Paquetes | Bytes |")
            out.append("|---|---|---|---|---|---|---|")
            for f in flows:
                svc, _ = port_info(f["dport"], f["l4"])
                out.append(
                    f"| {f['src']} | {f['dst']} | {f['l4']}/{f['dport'] or '-'} | "
                    f"{svc or '-'} | {md_escape(f['proto'])} | {f['pkts']:,} | "
                    f"{human(f['bytes'])} |"
                )
            out.append("")

    # --- control -------------------------------------------------------- #
    out.append("## 7. Operaciones de control observadas\n")
    ops = [o for c in caps for o in c.control_ops]
    if ops:
        agg = collections.Counter(
            (o["proto"], o["op"], o["src"], o["dst"]) for o in ops
        )
        out.append("| Protocolo | Operacion | Origen | Destino | Veces |")
        out.append("|---|---|---|---|---|")
        for (proto, op, src, dst), n in agg.most_common(args.max_rows):
            out.append(f"| {proto} | {md_escape(op)} | {src} | {dst} | {n} |")
    else:
        out.append("_No se observaron escrituras ni comandos de control. "
                   "Solo lectura e I/O ciclico._")
    out.append("")

    # --- brecha de visibilidad ------------------------------------------ #
    out.append("## 8. Brecha de visibilidad entre herramientas\n")
    out.append(
        "Cuando dos plataformas pasivas analizan la misma red y una reporta "
        "vulnerabilidades y la otra no, casi siempre es por una de estas razones. "
        "Las marcadas con **si** se confirmaron en estas capturas.\n"
    )
    if len(caps) > 1:
        out.append("### Que alcanza a ver cada punto de captura\n")
        out.append(
            "Dos sensores en puntos distintos producen inventarios distintos. "
            "Esta tabla muestra cuanto difiere la visibilidad entre los puntos "
            "capturados, que es el primer argumento a revisar antes de comparar "
            "conteos de hallazgos entre herramientas.\n"
        )
        out.append("| Captura | Equipos | Datos de identidad | Protocolos OT | "
                   "Operaciones de control | Duracion |")
        out.append("|---|---|---|---|---|---|")
        for c in caps:
            ot_protos = sorted({
                port_info(f["dport"], f["l4"])[0]
                for f in c.flows.values()
                if port_info(f["dport"], f["l4"])[1] == "ot"
            })
            out.append(
                f"| {c.name} | {len(c.hosts)} | {len(c.identity)} | "
                f"{', '.join(ot_protos) or '-'} | {len(c.control_ops)} | "
                f"{human_duration(c.info.get('Capture duration', ''))} |"
            )
        macs = [set(c.hosts) for c in caps]
        common = set.intersection(*macs) if macs else set()
        union = set.union(*macs) if macs else set()
        out.append(
            f"\nEquipos vistos por **todos** los puntos: **{len(common)}** de "
            f"**{len(union)}** en total. "
            f"Los {len(union) - len(common)} restantes solo son visibles desde "
            f"algunos puntos: un sensor conectado en un solo lugar nunca los "
            f"inventariaria, y por lo tanto nunca les asignaria vulnerabilidades.\n"
        )

    vis = [f for c in caps for f in c.findings if f["categoria"] == "Visibilidad"]
    vis_titles = {f["titulo"] for f in vis}
    out.append("| Causa posible | Confirmada aqui |")
    out.append("|---|---|")
    for label, title in VIS_CHECKS:
        out.append(f"| {label} | {'**si**' if title in vis_titles else 'no'} |")
    out.append("")
    out.append("Causas que esta captura no puede confirmar y hay que verificar "
               "con el cliente:\n")
    for q in VERIFY_WITH_CLIENT:
        out.append(f"- {strip_tags(q)}")
    out.append("")

    # --- preguntas ------------------------------------------------------ #
    out.append("## 9. Preguntas para la sesion con el cliente\n")
    for i, q in enumerate(CLIENT_QUESTIONS, 1):
        out.append(f"{i}. {q}")
    out.append("")

    report = outdir / "reporte_ot.md"
    report.write_text("\n".join(out), encoding="utf-8")
    return report


HTML_CSS = """
:root{
  --tinta:#15202b; --suave:#5b6b7c; --linea:#dde3ea; --fondo:#ffffff;
  --panel:#f6f8fa; --acento:#17486b; --acento2:#2d6f9e;
  --critica:#8b1a1a; --alta:#b4530a; --media:#8a6d00; --baja:#4a6b52;
  --critica-bg:#fdecea; --alta-bg:#fdf1e3; --media-bg:#fdf8e1; --baja-bg:#eef4ef;
}
*{box-sizing:border-box}
body{margin:0;background:var(--fondo);color:var(--tinta);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;}
.wrap{max-width:1180px;margin:0 auto;padding:0 32px 72px}
header.port{background:var(--acento);color:#fff;padding:44px 32px 36px;margin-bottom:34px}
header.port .inner{max-width:1180px;margin:0 auto}
header.port h1{margin:0 0 6px;font-size:28px;font-weight:650;letter-spacing:-.2px}
header.port p{margin:0;color:#cfe0ee;font-size:14.5px}
h2{font-size:20px;margin:44px 0 6px;padding-bottom:9px;border-bottom:2px solid var(--acento);
  font-weight:640;letter-spacing:-.2px}
h3{font-size:16px;margin:28px 0 8px;font-weight:620}
p.lead{color:var(--suave);margin:8px 0 18px;max-width:72ch}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0 8px}
.kpi{flex:1 1 140px;background:var(--panel);border:1px solid var(--linea);
  border-radius:8px;padding:14px 16px}
.kpi .n{font-size:26px;font-weight:660;line-height:1.1;font-variant-numeric:tabular-nums}
.kpi .l{font-size:12px;color:var(--suave);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.tbl{overflow-x:auto;margin:14px 0 8px;border:1px solid var(--linea);border-radius:7px}
.tbl table{margin:0;border-radius:7px}
table{border-collapse:collapse;width:100%;margin:14px 0 8px;font-size:13.5px}
th{background:var(--panel);text-align:left;font-weight:620;font-size:12px;
  text-transform:uppercase;letter-spacing:.4px;color:var(--suave);
  padding:9px 10px;border-bottom:2px solid var(--linea);white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid var(--linea);vertical-align:top}
tbody tr:nth-child(even){background:#fbfcfd}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.tag{display:inline-block;padding:1.5px 8px;border-radius:11px;font-size:11.5px;
  font-weight:620;white-space:nowrap}
.t-critica{background:var(--critica-bg);color:var(--critica)}
.t-alta{background:var(--alta-bg);color:var(--alta)}
.t-media{background:var(--media-bg);color:var(--media)}
.t-baja{background:var(--baja-bg);color:var(--baja)}
.t-info{background:#eef2f6;color:var(--suave)}
.cruza{color:var(--critica);font-weight:620}
.finding{border:1px solid var(--linea);border-left:4px solid var(--linea);
  border-radius:7px;padding:16px 20px;margin:16px 0;background:#fff;break-inside:avoid}
.finding.s-alta{border-left-color:var(--critica)}
.finding.s-media{border-left-color:var(--alta)}
.finding.s-baja{border-left-color:var(--media)}
.finding.s-informativa{border-left-color:#9fb0c0}
.finding h4{margin:0 0 4px;font-size:15.5px;font-weight:640}
.finding .meta{font-size:12px;color:var(--suave);margin-bottom:10px}
.finding .ev{background:var(--panel);border:1px solid var(--linea);border-radius:6px;
  padding:10px 12px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
  white-space:pre-wrap;word-break:break-word;margin:10px 0;max-height:280px;overflow:auto}
.finding dl{margin:8px 0 0}
.finding dt{font-weight:620;font-size:13px;margin-top:8px}
.finding dd{margin:2px 0 0;color:#30404f;font-size:13.5px}
.grid-matrix{overflow-x:auto;margin:14px 0}
.grid-matrix table{font-size:11.5px;width:auto}
.grid-matrix th.v{writing-mode:vertical-rl;transform:rotate(180deg);
  height:130px;padding:6px 3px;vertical-align:bottom}
.grid-matrix td{text-align:center;padding:5px 7px;min-width:26px}
.grid-matrix td.on{background:#dcebf5;font-weight:620;color:var(--acento)}
.grid-matrix td.ctl{background:var(--critica-bg);color:var(--critica);font-weight:680}
.grid-matrix th.row{text-align:left;white-space:nowrap;background:var(--panel);
  position:sticky;left:0;text-transform:none;font-size:11.5px}
.nota{background:var(--panel);border-left:3px solid var(--acento2);padding:11px 15px;
  margin:14px 0;font-size:13.5px;color:#30404f;border-radius:0 6px 6px 0}
ul.q{margin:10px 0;padding-left:22px}
ul.q li{margin:7px 0;max-width:80ch}
footer{margin-top:56px;padding-top:18px;border-top:1px solid var(--linea);
  color:var(--suave);font-size:12px}
@page{size:A4 landscape;margin:12mm}
@media print{
  body{font-size:9pt}
  .tbl{overflow:visible;border:none}
  table{font-size:8.5pt} th{font-size:7.5pt} .finding .ev{font-size:8pt}
  header.port{background:var(--acento) !important;-webkit-print-color-adjust:exact;
    print-color-adjust:exact}
  .wrap{max-width:none;padding:0 10mm}
  h2{break-after:avoid} table{break-inside:auto} tr{break-inside:avoid}
  .finding{break-inside:avoid} .ev{max-height:none;overflow:visible}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""


def _crit_tag(level: str) -> str:
    cls = {"Critica": "t-critica", "Alta": "t-alta", "Media": "t-media",
           "Baja": "t-baja", "Informativa": "t-info"}.get(level, "t-info")
    return f'<span class="tag {cls}">{esc(level)}</span>'


def write_html(caps: list[Capture], assets: dict, conduits: list[dict],
               outdir: Path, args) -> Path:
    now = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
    findings = [f for c in caps for f in c.findings]
    by_sev = collections.Counter(f["severidad"] for f in findings)
    h: list[str] = []
    a = h.append

    a("<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">")
    a("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    a(f"<title>{esc(args.titulo)}</title><style>{HTML_CSS}</style></head><body>")
    a('<header class="port"><div class="inner">')
    a(f"<h1>{esc(args.titulo)}</h1>")
    a(f"<p>{esc(args.cliente)} &middot; Analisis pasivo de trafico de red "
      f"&middot; Generado el {now}</p>")
    a("</div></header><div class=\"wrap\">")

    # ---------------- resumen ---------------- #
    ot_conduits = [c for c in conduits if c["categoria"] == "ot"]
    ctl_conduits = [c for c in conduits if c["escrituras"]]
    cross = [c for c in conduits if c["cruza_zona"]]
    a("<h2>Resumen</h2>")
    a('<div class="kpis">')
    for n, l in (
        (len(assets), "Activos"),
        (len(conduits), "Conductos"),
        (len(ot_conduits), "Conductos OT"),
        (len(ctl_conduits), "Con escritura"),
        (len(caps), "Capturas"),
        (sum(c.flow_packets for c in caps), "Paquetes"),
    ):
        a(f'<div class="kpi"><div class="n">{n:,}</div><div class="l">{esc(l)}</div></div>')
    a("</div>")
    a('<div class="kpis">')
    for sev in ("Alta", "Media", "Baja", "Informativa"):
        a(f'<div class="kpi"><div class="n">{by_sev.get(sev, 0)}</div>'
          f'<div class="l">Hallazgo {esc(sev.lower())}</div></div>')
    a("</div>")
    a('<div class="nota">Todo lo que sigue proviene exclusivamente del analisis '
      'pasivo de las capturas entregadas. No se genero trafico hacia la red del '
      'cliente. Los roles y zonas son inferidos del comportamiento observado y '
      'deben validarse con el personal de planta.</div>')

    # ---------------- inventario ---------------- #
    a("<h2>1. Inventario de activos</h2>")
    a('<p class="lead">Equipos identificados en las capturas, consolidados entre '
      'todos los puntos de monitoreo. Modelo y firmware provienen de los anuncios '
      'de descubrimiento (CDP, LLDP) y de los banners de servicio.</p>')
    a('<div class="tbl"><table><thead><tr><th>#</th><th>Equipo</th>'
      "<th>Direccion IP</th>"
      "<th>MAC</th><th>Fabricante</th><th>Modelo / descripcion</th>"
      "<th>Firmware</th><th>Rol inferido</th><th>Zona</th><th>VLAN</th>"
      "<th class=\"num\">Paquetes</th></tr></thead><tbody>")
    rows = sorted(assets.values(), key=lambda x: (-x["pkts"], x["mac"]))
    for i, ast in enumerate(rows, 1):
        a("<tr>"
          f"<td class=\"num\">{i}</td>"
          f"<td><strong>{esc(ast['nombre'])}</strong></td>"
          f"<td class=\"mono\">{esc(', '.join(sorted(ast['ips'])[:3]) or '—')}</td>"
          f"<td class=\"mono\">{esc(ast['mac'])}</td>"
          f"<td>{esc(ast['vendor'] or '—')}</td>"
          f"<td>{esc(ast.get('modelo') or '—')}</td>"
          f"<td class=\"mono\">{esc(ast.get('firmware') or '—')}</td>"
          f"<td>{esc(ast['role'] or 'Indeterminado')}</td>"
          f"<td>{esc(ast['purdue'] or '—')}</td>"
          f"<td>{esc(', '.join(sorted(ast['vlans'])) or '—')}</td>"
          f"<td class=\"num\">{ast['pkts']:,}</td></tr>")
    a("</tbody></table></div>")

    con_fw = [x for x in rows if x.get("firmware")]
    a(f'<div class="nota"><strong>{len(con_fw)} de {len(rows)}</strong> activos '
      f'revelaron version de firmware de forma pasiva. Solo sobre esos puede un '
      f'motor de vulnerabilidades hacer correspondencia con su base de CVEs; para '
      f'el resto haria falta sondeo activo o inventario manual.</div>')

    # ---------------- matriz de comunicaciones ---------------- #
    a("<h2>2. Matriz de comunicaciones</h2>")
    a('<p class="lead">Cada renglon es una relacion de comunicacion observada: '
      'un origen, un destino y un servicio. La criticidad combina el tipo de '
      'servicio, si cruza zonas y si transporta operaciones de escritura.</p>')
    a('<div class="tbl"><table><thead><tr><th>#</th><th>Origen</th><th>Zona</th>'
      "<th>Destino</th>"
      "<th>Zona</th><th>Servicio</th><th>Puerto</th><th>Sentido</th>"
      "<th class=\"num\">Paquetes</th><th class=\"num\">Volumen</th>"
      "<th class=\"num\">Escrituras</th><th>Criticidad</th></tr></thead><tbody>")

    def celda(nombre: str, ip: str) -> str:
        """Evita repetir la IP cuando el equipo no tiene nombre propio."""
        if nombre == ip:
            return f'<td class="mono">{esc(ip)}</td>'
        return (f"<td><strong>{esc(nombre)}</strong><br>"
                f'<span class="mono">{esc(ip)}</span></td>')

    for i, k in enumerate(conduits[: args.max_rows], 1):
        cruza = ' <span class="cruza">&#8594;</span>' if k["cruza_zona"] else ""
        a("<tr>"
          f"<td class=\"num\">{i}</td>"
          f"{celda(k['src_nombre'], k['src'])}"
          f"<td>{esc(k['src_zona'] or '—')}{cruza}</td>"
          f"{celda(k['dst_nombre'], k['dst'])}"
          f"<td>{esc(k['dst_zona'] or '—')}</td>"
          f"<td>{esc(k['servicio'])}</td>"
          f"<td class=\"mono\">{esc(k['l4'])}/{esc(k['port'] or '—')}</td>"
          f"<td>{'bidireccional' if k['bidireccional'] else 'unidireccional'}</td>"
          f"<td class=\"num\">{k['pkts']:,}</td>"
          f"<td class=\"num\">{human(k['bytes'])}</td>"
          f"<td class=\"num\">{format(k['escrituras'], ',') if k['escrituras'] else '—'}</td>"
          f"<td>{_crit_tag(k['criticidad'])}</td></tr>")
    a("</tbody></table></div>")
    if len(conduits) > args.max_rows:
        a(f'<div class="nota">Se muestran los {args.max_rows} conductos de mayor '
          f'criticidad y volumen. Los {len(conduits) - args.max_rows} restantes '
          f'estan en <code>comunicaciones.csv</code>.</div>')
    if cross:
        a(f'<div class="nota"><strong>{len(cross)} conductos cruzan zonas.</strong> '
          f'Son los candidatos naturales a control por firewall OT segun el modelo '
          f'de zonas y conductos de IEC 62443.</div>')

    # ---------------- rejilla ---------------- #
    srcs = sorted({k["src_nombre"] for k in conduits})
    dsts = sorted({k["dst_nombre"] for k in conduits})
    if len(srcs) <= 30 and len(dsts) <= 30:
        cell: dict[tuple, dict] = {}
        for k in conduits:
            c0 = cell.setdefault((k["src_nombre"], k["dst_nombre"]),
                                 {"svc": set(), "ctl": 0})
            c0["svc"].add(k["servicio"])
            c0["ctl"] += k["escrituras"]
        a("<h3>Vista de rejilla</h3>")
        a('<p class="lead">Filas: origen. Columnas: destino. En rojo, las '
          'relaciones que transportan escrituras al proceso.</p>')
        a('<div class="grid-matrix"><table><thead><tr><th class="row">Origen \\ Destino</th>')
        for d in dsts:
            a(f'<th class="v">{esc(d)}</th>')
        a("</tr></thead><tbody>")
        for s in srcs:
            a(f'<tr><th class="row">{esc(s)}</th>')
            for d in dsts:
                c0 = cell.get((s, d))
                if not c0:
                    a("<td></td>")
                elif c0["ctl"]:
                    a(f'<td class="ctl" title="{esc(", ".join(sorted(c0["svc"])))}">W</td>')
                else:
                    a(f'<td class="on" title="{esc(", ".join(sorted(c0["svc"])))}">&bull;</td>')
            a("</tr>")
        a("</tbody></table></div>")

    # ---------------- hallazgos ---------------- #
    a("<h2>3. Hallazgos</h2>")
    grouped: dict[tuple, dict] = {}
    for f in findings:
        k = (f["titulo"], f["severidad"])
        if k in grouped:
            grouped[k]["capturas"].append(f["captura"])
            grouped[k]["evidencia"] += f"\n\n({f['captura']}) " + f["evidencia"]
        else:
            gg = dict(f)
            gg["capturas"] = [f["captura"]]
            gg["evidencia"] = f"({f['captura']}) " + f["evidencia"]
            grouped[k] = gg
    ordered = sorted(grouped.values(),
                     key=lambda f: (SEV_ORDER.get(f["severidad"], 9), f["titulo"]))
    for i, f in enumerate(ordered, 1):
        a(f'<div class="finding s-{f["severidad"].lower()}">')
        a(f'<h4>{i}. {esc(f["titulo"])} {_crit_tag(f["severidad"])}</h4>')
        a(f'<div class="meta">{esc(f["categoria"])} &middot; '
          f'{esc(", ".join(sorted(set(f["capturas"]))))}</div>')
        a(f'<div class="ev">{esc(f["evidencia"])}</div>')
        a("<dl>")
        a(f"<dt>Por que importa</dt><dd>{esc(f['por_que_importa'])}</dd>")
        a(f"<dt>Recomendacion</dt><dd>{esc(f['recomendacion'])}</dd>")
        a("</dl></div>")

    # ---------------- visibilidad ---------------- #
    a("<h2>4. Alcance y brecha de visibilidad</h2>")
    a('<p class="lead">Dos plataformas pasivas conectadas en puntos distintos '
      'producen inventarios distintos. Antes de comparar conteos de hallazgos '
      'entre herramientas hay que igualar el punto de captura y la ventana.</p>')
    a("<table><thead><tr><th>Captura</th><th class=\"num\">Activos</th>"
      "<th class=\"num\">Datos de identidad</th><th>Protocolos OT</th>"
      "<th class=\"num\">Escrituras</th><th>Duracion</th></tr></thead><tbody>")
    for c in caps:
        ot = sorted({port_info(f["dport"], f["l4"])[0] for f in c.flows.values()
                     if port_info(f["dport"], f["l4"])[1] == "ot"})
        a(f"<tr><td>{esc(c.name)}</td><td class=\"num\">{len(c.hosts)}</td>"
          f"<td class=\"num\">{len(c.identity)}</td><td>{esc(', '.join(ot) or '—')}</td>"
          f"<td class=\"num\">{len(c.control_ops):,}</td>"
          f"<td>{esc(human_duration(c.info.get('Capture duration', '')))}</td></tr>")
    a("</tbody></table>")
    if len(caps) > 1:
        macs = [set(c.hosts) for c in caps]
        common, union = set.intersection(*macs), set.union(*macs)
        a(f'<div class="nota">Equipos visibles desde <strong>todos</strong> los '
          f'puntos: <strong>{len(common)}</strong> de <strong>{len(union)}</strong>. '
          f'Un sensor conectado en un solo punto nunca inventariaria los '
          f'{len(union) - len(common)} restantes, y por lo tanto nunca les '
          f'asignaria vulnerabilidades.</div>')

    vis_titles = {f["titulo"] for f in findings if f["categoria"] == "Visibilidad"}
    a("<h3>Causas tecnicas de una diferencia entre herramientas</h3>")
    a("<table><thead><tr><th>Causa</th><th>Confirmada en estas capturas</th>"
      "</tr></thead><tbody>")
    for label, title in VIS_CHECKS:
        marca = "<strong>Si</strong>" if title in vis_titles else "No"
        a(f"<tr><td>{esc(label)}</td><td>{marca}</td></tr>")
    a("</tbody></table>")
    a("<h3>Pendiente de verificar con el cliente</h3><ul class=\"q\">")
    for q in VERIFY_WITH_CLIENT:
        a(f"<li>{q}</li>")
    a("</ul>")

    a("<h2>5. Preguntas para la sesion</h2><ul class=\"q\">")
    for q in CLIENT_QUESTIONS:
        a(f"<li>{esc(q)}</li>")
    a("</ul>")

    a(f"<footer>Generado con ot_pcap_assess.py el {now}. "
      f"Analisis pasivo sobre {len(caps)} captura(s). "
      f"Los roles, zonas y criticidades son inferidos y requieren validacion "
      f"con el personal de planta.</footer>")
    a("</div></body></html>")

    path = outdir / "reporte_ot.html"
    path.write_text("\n".join(h), encoding="utf-8")
    return path


def write_csvs(caps: list[Capture], assets: dict, conduits: list[dict],
               outdir: Path) -> None:
    # Inventario consolidado: un renglon por equipo, no por equipo y captura.
    with open(outdir / "inventario.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["equipo", "ips", "mac", "fabricante", "modelo_descripcion",
                    "firmware", "rol_inferido", "zona_purdue", "vlans",
                    "base_inferencia", "puertos_servidos", "protocolos",
                    "paquetes", "bytes", "visto_en_capturas"])
        for a in sorted(assets.values(), key=lambda x: (-x["pkts"], x["mac"])):
            w.writerow([
                a["nombre"], ";".join(sorted(a["ips"])), a["mac"], a["vendor"],
                a.get("modelo", ""), a.get("firmware", ""), a["role"], a["purdue"],
                ";".join(sorted(a["vlans"])), a["role_why"],
                ";".join(f"{p}/{l4}" for (p, l4) in a["ports_served"]),
                ";".join(f"{p}={n}" for p, n in a["protos"].most_common(12)),
                a["pkts"], a["bytes"], ";".join(sorted(a["capturas"])),
            ])

    with open(outdir / "comunicaciones.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["origen", "origen_ip", "origen_rol", "origen_zona",
                    "destino", "destino_ip", "destino_rol", "destino_zona",
                    "servicio", "l4", "puerto", "categoria", "sentido",
                    "cruza_zona", "escrituras", "criticidad", "paquetes",
                    "bytes", "capturas"])
        for k in conduits:
            w.writerow([
                k["src_nombre"], k["src"], k["src_rol"], k["src_zona"],
                k["dst_nombre"], k["dst"], k["dst_rol"], k["dst_zona"],
                k["servicio"], k["l4"], k["port"], k["categoria"],
                "bidireccional" if k["bidireccional"] else "unidireccional",
                "si" if k["cruza_zona"] else "no", k["escrituras"],
                k["criticidad"], k["pkts"], k["bytes"], ";".join(sorted(k["capturas"])),
            ])

    with open(outdir / "activos.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["captura", "mac", "fabricante", "ips", "vlans", "rol_inferido",
                    "nivel_purdue", "base_inferencia", "hostnames", "puertos_servidos",
                    "paquetes_tx", "paquetes_rx", "bytes_tx", "bytes_rx", "fingerprints"])
        for c in caps:
            for h in c.hosts.values():
                w.writerow([
                    c.name, h["mac"], h["vendor"], ";".join(sorted(h["ips"])),
                    ";".join(sorted(h["vlans"])), h.get("role", ""), h.get("purdue", ""),
                    h.get("role_why", ""), ";".join(sorted(h["hostnames"])),
                    ";".join(f"{p}/{l4}" for (p, l4) in h["ports_served"]),
                    h["tx_pkts"], h["rx_pkts"], h["tx_bytes"], h["rx_bytes"],
                    " | ".join(sorted(h["fingerprints"])),
                ])

    with open(outdir / "flujos.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["captura", "origen", "destino", "l4", "puerto_destino",
                    "servicio", "protocolo", "paquetes", "bytes"])
        for c in caps:
            for f in sorted(c.flows.values(), key=lambda x: -x["pkts"]):
                svc, _ = port_info(f["dport"], f["l4"])
                w.writerow([c.name, f["src"], f["dst"], f["l4"], f["dport"],
                            svc, f["proto"], f["pkts"], f["bytes"]])

    with open(outdir / "identidad.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["captura", "origen_ip", "origen_mac", "tipo", "valor", "detalle"])
        for c in caps:
            for i in c.identity:
                w.writerow([c.name, i["ip"], i["mac"], i["tipo"], i["valor"], i["detalle"]])

    with open(outdir / "hallazgos.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["captura", "severidad", "categoria", "titulo", "evidencia",
                    "por_que_importa", "recomendacion"])
        for c in caps:
            for f in sorted(c.findings, key=lambda x: SEV_ORDER.get(x["severidad"], 9)):
                w.writerow([c.name, f["severidad"], f["categoria"], f["titulo"],
                            f["evidencia"], f["por_que_importa"], f["recomendacion"]])

    with open(outdir / "control.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["captura", "trama", "protocolo", "operacion", "origen", "destino", "detalle"])
        for c in caps:
            for o in c.control_ops:
                w.writerow([c.name, o["frame"], o["proto"], o["op"], o["src"],
                            o["dst"], o["detalle"]])


def write_json(caps: list[Capture], outdir: Path) -> None:
    data = []
    for c in caps:
        data.append({
            "archivo": str(c.path),
            "metadatos": c.info,
            "protocolos": c.protos,
            "paquetes_analizados": c.flow_packets,
            "muestreado": c.sampled,
            "activos": [
                {k: (sorted(v) if isinstance(v, set)
                     else dict(v) if isinstance(v, collections.Counter) else v)
                 for k, v in h.items()
                 if k not in ("ports_served", "ports_used", "proto_seen")}
                | {"puertos_servidos": [f"{p}/{l}" for (p, l) in h["ports_served"]],
                   "protocolos": dict(h["proto_seen"])}
                for h in c.hosts.values()
            ],
            "identidad": c.identity,
            "control": c.control_ops,
            "texto_claro": c.cleartext,
            "hallazgos": c.findings,
        })
    (outdir / "resultado.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def collect_inputs(paths: list[str]) -> list[Path]:
    exts = {".pcap", ".pcapng", ".cap", ".pcapng.gz", ".pcap.gz"}
    found: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            for f in sorted(pp.rglob("*")):
                if f.is_file() and (f.suffix.lower() in exts
                                    or f.name.lower().endswith((".pcap.gz", ".pcapng.gz"))):
                    found.append(f)
        elif pp.is_file():
            found.append(pp)
        else:
            print(f"[!] No existe: {p}", file=sys.stderr)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Analisis OT de capturas de red para assessment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("inputs", nargs="+", help="Archivos .pcap/.pcapng o carpetas")
    ap.add_argument("-o", "--out", default="reporte_ot", help="Carpeta de salida")
    ap.add_argument("--tshark", help="Carpeta de Wireshark si no esta en el PATH")
    ap.add_argument("--max-packets", type=int, default=1_000_000,
                    help="Tope de paquetes para el mapa de flujos (0 = todos). "
                         "Por defecto 1000000.")
    ap.add_argument("--max-rows", type=int, default=120,
                    help="Filas maximas por tabla en los reportes")
    ap.add_argument("--titulo", default="Assessment de ciberseguridad OT",
                    help="Titulo que aparece en la portada del reporte HTML")
    ap.add_argument("--cliente", default="Analisis de trafico de planta",
                    help="Subtitulo de la portada: nombre del cliente o del sitio")
    ap.add_argument("--no-detail", action="store_true",
                    help="Omitir el pase de detalle (mas rapido, sin identidad ni control)")
    args = ap.parse_args()

    files = collect_inputs(args.inputs)
    if not files:
        print("[!] No hay capturas que analizar.", file=sys.stderr)
        return 1

    tshark_bin = find_tool("tshark", args.tshark)
    capinfos_bin = find_tool("capinfos", args.tshark)
    editcap_bin = find_tool("editcap", args.tshark)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    ts = Tshark(tshark_bin, capinfos_bin, editcap_bin, outdir / ".probe")
    print(f"[*] tshark: {tshark_bin}")
    ts.make_probe(files[0])

    flow_fields = ts.valid_fields(FLOW_FIELDS)
    detail_fields = ts.valid_fields(DETAIL_FIELDS)
    detail_filter = ts.valid_filter(DETAIL_FILTER_PARTS)
    dropped = set(DETAIL_FIELDS) - set(detail_fields)
    if dropped:
        print(f"[*] Campos no soportados por este tshark (ignorados): "
              f"{', '.join(sorted(dropped))}")

    caps: list[Capture] = []
    for i, f in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] {f.name} ({human(f.stat().st_size)})")
        cap = Capture(f)
        print("    - metadatos...")
        cap.info = ts.capinfos(f)
        print("    - jerarquia de protocolos...")
        cap.protos = ts.phs(f)
        print(f"    - flujos y activos"
              f"{f' (muestra de {args.max_packets:,})' if args.max_packets else ''}...")
        analyze_flows(ts, cap, flow_fields, args.max_packets)
        if not args.no_detail:
            print("    - identidad, control y anomalias...")
            analyze_detail(ts, cap, detail_fields, detail_filter)
        infer_roles(cap)
        evaluate(cap)
        evaluate_visibility(cap)
        print(f"    => {len(cap.hosts)} equipos, {len(cap.flows)} flujos, "
              f"{len(cap.identity)} datos de identidad, "
              f"{len(cap.control_ops)} operaciones de control, "
              f"{len(cap.findings)} hallazgos")
        caps.append(cap)

    print("\n[*] Consolidando inventario y matriz de comunicaciones...")
    assets, ip_index = merge_assets(caps)
    conduits = build_conduits(caps, ip_index)
    print(f"    => {len(assets)} activos unicos, {len(conduits)} conductos "
          f"({sum(1 for k in conduits if k['cruza_zona'])} cruzan zonas)")

    print("[*] Escribiendo reportes...")
    report = write_report(caps, assets, conduits, outdir, args)
    html = write_html(caps, assets, conduits, outdir, args)
    write_csvs(caps, assets, conduits, outdir)
    write_json(caps, outdir)

    probe = outdir / ".probe"
    if probe.exists():
        for p in probe.iterdir():
            p.unlink(missing_ok=True)
        probe.rmdir()

    print(f"\n[OK] {html}   <- reporte presentable a cliente")
    print(f"     {report}")
    for n in ("inventario.csv", "comunicaciones.csv", "activos.csv", "flujos.csv",
              "identidad.csv", "hallazgos.csv", "control.csv", "resultado.json"):
        print(f"     {outdir / n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
