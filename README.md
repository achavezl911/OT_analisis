# ot_analisis

Análisis pasivo de capturas de red (`pcap` / `pcapng`) desde el punto de vista OT.
A partir de una o varias capturas genera un **inventario de activos**, una
**matriz de comunicaciones** y un **reporte de hallazgos** listo para presentar
a cliente.

Nace de una pregunta concreta de campo: *un cliente reporta que sobre las mismas
capturas una plataforma encuentra vulnerabilidades y otra no*. El reporte incluye
una sección dedicada a esa brecha, con las causas técnicas que la herramienta
puede confirmar desde la captura y las que hay que verificar con el cliente.

## Requisitos

Python 3.9 o superior y Wireshark (se usan `tshark`, `capinfos` y `editcap`).

```bash
# Debian / Ubuntu
sudo apt install tshark

# RHEL / Rocky / Alma
sudo dnf install wireshark-cli

# macOS
brew install --cask wireshark
```

En Windows basta instalar Wireshark; el script lo localiza solo en
`C:\Program Files\Wireshark`. En cualquier sistema se puede forzar la ruta con
`--tshark`.

No hace falta `sudo` para ejecutarlo: solo lee archivos, nunca captura tráfico.

## Uso

```bash
python ot_pcap_assess.py capturas/ -o reporte/
```

```bash
python ot_pcap_assess.py planta.pcapng -o reporte/ \
  --titulo "Assessment de ciberseguridad OT" \
  --cliente "Central de generación X"
```

Acepta archivos sueltos, varias rutas o un directorio (que recorre de forma
recursiva).

### Opciones

| Opción | Para qué sirve |
|---|---|
| `-o, --out` | Carpeta de salida. Por defecto `reporte_ot`. |
| `--titulo` | Título de la portada del HTML. |
| `--cliente` | Subtítulo de la portada: cliente o sitio. |
| `--max-packets` | Tope de paquetes para el mapa de flujos. `0` procesa todo. Por defecto 1 000 000. |
| `--max-rows` | Filas máximas por tabla en los reportes. Por defecto 120. |
| `--no-detail` | Omite el pase de detalle. Mucho más rápido, pero sin identidad ni operaciones de control. |
| `--tshark` | Carpeta donde está Wireshark, si no se encuentra en el `PATH`. |

## Qué genera

| Archivo | Contenido |
|---|---|
| `reporte_ot.html` | Reporte presentable a cliente. Autocontenido, imprimible a PDF en horizontal. |
| `reporte_ot.md` | El mismo contenido en Markdown, para anexo técnico. |
| `inventario.csv` | Un renglón por activo: nombre, IP, MAC, fabricante, modelo, firmware, rol y zona. |
| `comunicaciones.csv` | Matriz de comunicaciones completa, un renglón por conducto. |
| `identidad.csv` | Cada dato de identidad observado y de qué paquete salió. |
| `control.csv` | Cada operación de escritura o comando, con número de trama. |
| `hallazgos.csv` | Hallazgos con evidencia y recomendación. |
| `flujos.csv`, `activos.csv` | Detalle por captura, sin consolidar. |
| `resultado.json` | Todo lo anterior, para alimentar otra herramienta. |

## Qué analiza

**Inventario.** Fabricante por OUI, hostname (DHCP, NetBIOS, CDP, LLDP, SMB),
modelo y firmware cuando el equipo los anuncia. Rol y nivel Purdue inferidos del
comportamiento: qué puertos atiende, cuáles consulta y qué protocolos habla.

**Matriz de comunicaciones.** Un renglón por relación origen → destino →
servicio, con volumen, sentido, si cruza zonas y si transporta escrituras. La
criticidad combina esos factores. Incluye una vista de rejilla cuando el número
de activos lo permite.

**Protocolos OT.** Modbus/TCP, DNP3, IEC 60870-5-104, IEC 61850 (MMS, GOOSE, SV),
EtherNet/IP y CIP, S7comm, PROFINET, BACnet, OPC UA, FINS, MELSEC, GE SRTP y
PTP, entre otros.

**Operaciones de control.** Separa lectura de escritura. Detecta escrituras CIP
(incluidas las anidadas en Multiple Service Packet), funciones de escritura
Modbus, Operate y Direct Operate de DNP3, comandos IEC-104, y descarga, arranque
o paro de PLC en S7comm. Cada operación se cuenta una sola vez, en la petición.

**Hallazgos.** Alrededor de veinte reglas: protocolos de descubrimiento de
Windows en la red de control, credenciales en texto claro, SNMP v1/v2c, software
fuera de soporte, direcciones APIPA, salida a Internet, subredes conviviendo en
un mismo dominio de difusión, conflictos de ARP, barridos y escaneos, tormentas
de difusión e inestabilidad de STP.

**Brecha de visibilidad.** Trunca­miento de captura, SPAN unidireccional, punto
que solo ve difusión, ausencia de paquetes de identidad, tráfico dominado por
I/O cíclico, ventana corta y pérdida de etiquetas VLAN. Cuando se analizan
varias capturas, compara qué alcanza a ver cada punto.

## Notas de interpretación

Los roles, zonas y criticidades son **inferidos del tráfico observado**, no
declarados por los equipos. Hay que validarlos con el personal de planta antes
de usarlos en una entrega.

El script **no emite identificadores de CVE**. Extrae el fingerprint exacto
(fabricante, modelo, versión) y lo presenta para contrastarlo contra el aviso de
seguridad del fabricante: Cisco PSIRT, Siemens SSA, Rockwell SD, Belden, Moxa.
Es a propósito: una base de CVEs embebida envejece mal y lleva a afirmar cosas
que no se sostienen frente al cliente.

La ausencia de un hallazgo no prueba la ausencia del riesgo. Si la captura no
contiene los paquetes que revelan identidad, ninguna herramienta pasiva —esta ni
ninguna otra— puede enumerar vulnerabilidades. Esa es justamente la lectura que
la sección de brecha de visibilidad busca dejar documentada.

## Manejo de datos del cliente

Las capturas y los reportes generados contienen direccionamiento, inventario y
topología de la planta. El `.gitignore` de este repositorio los excluye a
propósito. Conviene no versionarlos ni moverlos fuera del canal acordado con el
cliente.
