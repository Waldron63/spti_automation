# Automation

Este repositorio contiene un conjunto de scripts de Python para realizar análisis de seguridad y automatización de tareas relacionadas.

## Integrantes

Juan David Martínez Méndez - [@Fataltester](https://github.com/Fataltester)

Santiago Gualdrón Rincón - [@Waldron63](https://github.com/Waldron63)

## Introducción

El objetivo de este proyecto es proporcionar herramientas para el análisis de logs, escaneo de redes y procesamiento de resultados de seguridad. Cada script está diseñado para una tarea específica, facilitando la automatización de flujos de trabajo en auditorías de seguridad.

## Prerrequisitos

Asegúrate de tener instaladas las siguientes herramientas en tu sistema.

-   **Python 3:**
    ```bash
    python3 --version
    ```

-   **Git:**
    ```bash
    git -v
    ```

## Instalación

Sigue estos pasos para configurar el proyecto en tu entorno local.

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/Waldron63/spti_automation.git
    cd spti_automation
    ```

2.  **Ejecutar los scripts:**
    -   **Análisis de concurrencia**
        ```bash
        python3 scanner.py 127.0.0.1 --ports 1-1024 --rate 200 --timeout 0.5 --mode thread
        ```
    -   **Parseo de escaneo Nmap:**
        ```bash
        nmap -sV --open --stats-every 15s -oX sample_output/scan.xml 192.168.1.0/24

        python3 parse_scan.py --input sample_output/scan.xml --output sample_output/hosts.json
        ```
    -   **Análisis de logs de autenticación:**
        ```bash
        python3 auth_analysis.py sample_output/auth.log
        ```
    -   **Análisis de logs de acceso:**
        ```bash
        python3 log_analysis.py sample_output/access.log
        ```
    -   **Herramienta de reconocimiento integrada:**
        ```bash
        python3 recon.py scanme.nmap.org --output ./sample_output --verbose
        ```

## Entorno

La estructura del proyecto es la siguiente:

```
spti_automation/
├── scanner.py          # Part 1: concurrent port scanner
├── parse_scan.py       # Part 2: nmap XML parser and enricher
├── auth_analysis.py    # Part 3: auth log analysis
├── log_analysis.py     # Part 3: web log analysis + anomaly detection
├── recon.py            # Part 4: integrated tool
├── README.md           # Setup instructions and per-script explanation
├── docs/
│   ├── part1.md
│   ├── part2.md
│   ├── part3.md
│   └── part4.md
└── sample_output/
    ├── access.log
    ├── audit.log
    ├── auth.log
    ├── hosts.json
    ├── report.md
    ├── results.json
    ├── scan.xml
    └── stdout.txt
```

## Marco Teórico

En cada uno de los siguientes archivos, se encuentra la solución de cada punto, con la respuesta a sus respectivas preguntas, ejecuciones o secciones:

-   [Part 1: From sequential to concurrent scanner](./docs/part1.md)
-   [Part 2: Structured output and enrichment](./docs/part2.md)
-   [Part 3: Log analysis and anomaly detection](./docs/part3.md)
-   [Part 4: Integrated reconnaissance tool](./docs/part4.md)

## Construido Con

-   [Python](https://www.python.org/) - Lenguaje de programación principal.
-   [Nmap](https://nmap.org/) - Utilizado por `scanner.py` para el escaneo de redes.
-   [Git y GitHub](https://git-scm.com/) - Control de versiones y alojamiento del código
