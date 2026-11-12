# Proyecto 01 — Detection-as-Code lab

> Notas de trabajo para Claude Code, en español. Este repo es **público**: aquí no va nada personal ni datos de ninguna empresa. La cara pública es el `README.md` (en inglés).

## Objetivo
Un repositorio que demuestra el ciclo completo de detection engineering: reglas de detección como código, validadas, convertidas a Splunk y probadas automáticamente contra logs de ataques reales.

## Versión mínima (MVP)
- Reglas **Sigma** para técnicas comunes de **MITRE ATT&CK** en Windows:
  - [x] T1685.005 Borrado de logs de eventos (antes T1070.001): Security 1102 y System 104.
  - [x] T1059.001 PowerShell con comando codificado (Sysmon 1).
  - [x] T1003.001 Volcado de memoria de LSASS (Sysmon 10).
  - [ ] T1543.003 Creación de servicio.
  - [ ] T1053.005 Tarea programada.
- Conversión automática de cada regla a **Splunk SPL**.
- Tests por regla: muestras de ataque reales (número exacto de coincidencias), variantes de ataque inventadas que deben disparar y eventos benignos parecidos que no.
- **GitHub Actions**: en cada cambio valida, convierte y ejecuta los tests.
- README en inglés que se entiende en 2 minutos.

## Fuera del MVP (fases siguientes)
- Splunk real en Docker para probar el SPL generado (y cerrar el desfase de nombres de campo Sigma ↔ Splunk).
- Más reglas y fuentes de logs (Sysmon, Linux, cloud).
- Mapa de cobertura de ATT&CK (ATT&CK Navigator).
- Despliegue automático de reglas a un SIEM.

## Reparto del trabajo
- **Claude**: infraestructura y automatización (estructura del repo, scripts de Python, tests, CI). Lo explica mientras lo construye.
- **Matt**: la lógica de detección (qué detectar, por qué, falsos positivos), con guía de Claude.

## Datos
Solo datasets públicos; **nunca** datos de una empresa. Las muestras no se suben al repo: los tests las descargan de un commit fijado y verifican su SHA-256 (`datasets.yml` + `tests/cases/`). Los eventos benignos son inventados.

## Stack
- Python 3.12 gestionado con `uv`; `uv.lock` fija las versiones exactas.
- pySigma 2.x con dos backends: `sqlite` (motor de tests local) y `splunk` (SPL).
- Pipelines: `sysmon` + `windows-logsources` (local) y `sysmon` + `splunk_windows` (Splunk). Mismas suposiciones de fuente de log en ambos (`src/detlab/pipelines.py`).
- `evtx` (parser en Rust) para leer `.evtx`; `sigma-cli` para `sigma check`; pytest.
- GitHub Actions con acciones fijadas por SHA y permisos de solo lectura.

## Estructura
```
rules/windows/*.yml         reglas Sigma
tests/cases/<regla>.yml     caso de test de cada regla (muestras + benignos)
tests/test_rules.py         tests genéricos para todas las reglas
tests/test_engine.py        tests del motor (aplanado de eventos, SQLite)
splunk/<regla>.spl          SPL generado; se commitea y la CI falla si está desactualizado
src/detlab/                 events, engine, convert, samples, pipelines, cli
datasets.yml                origen, licencia y commit fijado de cada dataset
.github/workflows/ci.yml    CI
```

## Cómo añadir una regla
1. `uv run detlab show <log.evtx>` para ver los campos de los eventos.
2. Escribir `rules/windows/<nombre>.yml` (UUID nuevo, tags de ATT&CK vigentes).
3. Crear `tests/cases/<nombre>.yml`: muestras (`sha256` + `expected_matches`), `attack_events` opcionales (variantes que deben disparar) y `benign_events` (`name`, `why`, `event`). Los eventos inventados llevan `Channel` y `EventID` reales (p. ej. Sysmon 1), porque el pipeline los exige.
4. `uv run detlab convert`, `uv run sigma check --fail-on-issues rules/`, `uv run pytest`.
5. Opcional: *mutation testing*, es decir, estropear la regla a propósito (quitar un filtro, un espacio…) y comprobar que algún test falla.

Para encontrar muestras: clonar EVTX-ATTACK-SAMPLES (`git clone --depth 1`, ~46 MB) en una carpeta temporal y recorrer los `.evtx` con `detlab.events.load_evtx` buscando el patrón.

## Convenciones y avisos
- Aplanado de EVTX: `System` → `EventID`, `Channel`, `Provider_Name`…; `EventData`/`UserData` → un campo por dato. Si un dato choca con un campo de cabecera, se guarda como `<Contenedor>_<campo>` (p. ej. `UserData_Channel` en el 104 = log borrado). Los nombres no distinguen mayúsculas.
- `Execution_ProcessID` es el PID del proceso que **escribe** el evento; no confundir con `ProcessId` de `EventData`.
- `sigma check` valida los tags contra el ATT&CK **vigente** (lo descarga en cada ejecución). Si MITRE revoca una técnica, la CI se pone en rojo. Ya pasó: ATT&CK 20.1 (nov 2026) revocó T1070.001 en favor de T1685.005; TA0005 pasó a llamarse *Stealth* y apareció *Defense Impairment* (TA0112).
- `process_creation` → el pipeline `sysmon` lo convierte en Sysmon evento 1. Security 4688 **no** está cubierto todavía (haría falta otro pipeline o una regla aparte).
- `process_access` → Sysmon evento 10 (`SourceImage`, `TargetImage`, `GrantedAccess` en hexadecimal como texto, p. ej. `'0x1fffff'`).
- Exclusiones siempre por **ruta completa** (`startswith` carpeta + `endswith` ejecutable), nunca solo por nombre. Cada exclusión lleva un `attack_event` con el mismo nombre en otra carpeta.
- Huecos conocidos: se dejan como muestra con `expected_matches: 0` y un comentario `KNOWN GAP`, para que sigan a la vista.
- El antivirus del equipo de desarrollo puede bloquear comandos que contengan nombres de herramientas de ataque (p. ej. al hashear muestras). Esos nombres van dentro de scripts o archivos, no en la línea de comandos. No se desactiva el antivirus.
- `windash` expande `-` a `/`, `–`, `—`, `―`. En Splunk cada variante es un OR más (ver `splunk/win_powershell_encoded_command.spl`).
- Desfase conocido: los nombres de campo Sigma (`Provider_Name`) no siempre coinciden con los del add-on de Windows de Splunk. Se valida en la fase de Splunk real.

## Estado
- 2026-11-12: pipeline montado (validación, conversión a SPL, tests contra EVTX-ATTACK-SAMPLES, CI). Primera técnica completa: T1685.005 (dos reglas). Repo publicado con la CI en verde.
- 2026-11-12: T1059.001 PowerShell codificado (Image/OriginalFileName + abreviaturas de -EncodedCommand con windash; medium). Tests: 3 logs reales, 6 variantes inventadas, 4 benignos. Nuevo en los casos de test: `attack_events`.
- 2026-11-12: T1003.001 acceso a LSASS (Sysmon 10, máscaras de volcado conocidas, Defender excluido por ruta; high). 12 logs reales (10 volcados detectados; MalSeclogon = hueco conocido por 0x1410; `ps` de Meterpreter = descubrimiento, 0), 2 variantes, 4 benignos; 4 mutaciones cazadas. 55 tests. Siguiente: T1543.003 o T1053.005.
