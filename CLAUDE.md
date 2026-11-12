# Proyecto 01 — Detection-as-Code lab

> Notas de trabajo para Claude Code, en español. Este repo es **público**: aquí no va nada personal ni datos de ninguna empresa. La cara pública es el `README.md` (en inglés).

## Objetivo
Un repositorio que demuestra el ciclo completo de detection engineering: reglas de detección como código, validadas, convertidas a Splunk y probadas automáticamente contra logs de ataques reales.

## Versión mínima (MVP)
- Reglas **Sigma** para técnicas comunes de **MITRE ATT&CK** en Windows:
  - [x] T1685.005 Borrado de logs de eventos (antes T1070.001): Security 1102 y System 104.
  - [ ] T1059.001 PowerShell con comando codificado.
  - [ ] T1003.001 Volcado de memoria de LSASS.
  - [ ] T1543.003 Creación de servicio.
  - [ ] T1053.005 Tarea programada.
- Conversión automática de cada regla a **Splunk SPL**.
- Tests por regla: muestras de ataque reales (número exacto de coincidencias) y eventos benignos parecidos que no deben disparar.
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
3. Crear `tests/cases/<nombre>.yml`: muestras (`sha256` + `expected_matches`) y eventos benignos (`name`, `why`, `event`).
4. `uv run detlab convert`, `uv run sigma check --fail-on-issues rules/`, `uv run pytest`.

## Convenciones y avisos
- Aplanado de EVTX: `System` → `EventID`, `Channel`, `Provider_Name`…; `EventData`/`UserData` → un campo por dato. Si un dato choca con un campo de cabecera, se guarda como `<Contenedor>_<campo>` (p. ej. `UserData_Channel` en el 104 = log borrado). Los nombres no distinguen mayúsculas.
- `Execution_ProcessID` es el PID del proceso que **escribe** el evento; no confundir con `ProcessId` de `EventData`.
- `sigma check` valida los tags contra el ATT&CK **vigente** (lo descarga en cada ejecución). Si MITRE revoca una técnica, la CI se pone en rojo. Ya pasó: ATT&CK 20.1 (nov 2026) revocó T1070.001 en favor de T1685.005; TA0005 pasó a llamarse *Stealth* y apareció *Defense Impairment* (TA0112).
- Desfase conocido: los nombres de campo Sigma (`Provider_Name`) no siempre coinciden con los del add-on de Windows de Splunk. Se valida en la fase de Splunk real.

## Estado
- 2026-11-12: pipeline montado (validación, conversión a SPL, tests contra EVTX-ATTACK-SAMPLES, CI). Primera técnica completa: T1685.005 (dos reglas). Siguiente: T1059.001.
