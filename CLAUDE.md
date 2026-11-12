# Proyecto 01 — Detection-as-Code lab

> Notas de trabajo para Claude Code, en español. Este repo es **público**: aquí no va nada personal ni datos de ninguna empresa. La cara pública es el `README.md` (en inglés).

## Objetivo
Un repositorio que demuestra el ciclo completo de detection engineering: reglas de detección como código, validadas, convertidas a Splunk y probadas automáticamente contra logs de ataques reales.

## Versión mínima (MVP)
- Reglas **Sigma** para técnicas comunes de **MITRE ATT&CK** en Windows:
  - [x] T1685.005 Borrado de logs de eventos (antes T1070.001): Security 1102 y System 104.
  - [x] T1059.001 PowerShell con comando codificado (Sysmon 1).
  - [x] T1003.001 Volcado de memoria de LSASS (Sysmon 10).
  - [x] T1543.003 Creación de servicio (System 7045 y Sysmon 13).
  - [x] T1053.005 Tarea programada (Security 4698/4702 y schtasks en Sysmon 1).
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
tests/cases/<regla>.yml     caso de test de cada regla (muestras, variantes, benignos, mutaciones)
tests/test_rules.py         tests genéricos para todas las reglas
tests/test_engine.py        tests del motor (aplanado de eventos, SQLite)
tests/test_mutation.py      tests de las ediciones y veredictos de las mutaciones
splunk/<regla>.spl          SPL generado; se commitea y la CI falla si está desactualizado
src/detlab/                 events, engine, convert, samples, pipelines, mutation, cli
datasets.yml                origen, licencia y commit fijado de cada dataset
.github/workflows/ci.yml    CI
```

## Cómo añadir una regla
1. `uv run detlab show <log.evtx>` para ver los campos de los eventos.
2. Escribir `rules/windows/<nombre>.yml` (UUID nuevo, tags de ATT&CK vigentes).
3. Crear `tests/cases/<nombre>.yml`: muestras (`sha256` + `expected_matches`), `attack_events` opcionales (variantes que deben disparar) y `benign_events` (`name`, `why`, `event`). Los eventos inventados llevan `Channel` y `EventID` reales (p. ej. Sysmon 1), porque el pipeline los exige.
4. Añadir `mutations:` al caso: una por decisión de diseño de la regla (filtro, exclusión, indicador clave, espacio, `windash`…), cada una con `name`, `why` y `edits`. `delete: <texto>` borra la línea que lo contiene y todo lo que cuelga de ella; `replace: <texto>` + `with: <texto>` lo sustituye. El texto tiene que aparecer **una sola vez** en la regla (cuidado con la descripción y los comentarios).
5. `uv run detlab convert`, `uv run sigma check --fail-on-issues rules/`, `uv run pytest`. `uv run detlab mutate <regla>` dice qué comprobación caza cada mutación. Si una sobrevive, o falta un test (se añade) o esa parte de la regla no aporta nada (se quita). Si no se puede cazar a propósito, se declara con `survives: <motivo>`.

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
- `registry_set` → Sysmon evento 13 (`TargetObject` = clave, `Details` = valor). Para claves de servicio se usa `ControlSet` y no solo `CurrentControlSet`, porque se puede escribir en `ControlSet001`.
- Lista de mapas en una selección (`- campo1: … / - campo2: …`) = OR entre ellos. `campo|contains|all` = todos los valores a la vez.
- Nombres cortos como `cmd` no se buscan como subcadena suelta (casarían con `remotecmd.exe`): al principio (`startswith`) o detrás de `\`.
- Condiciones defensivas sin test que las aísle (`Provider_Name` en 1102, 104, 7045 y 4698/4702): se aceptan, por coherencia con lo que decidió Matt en la primera regla, y quedan como mutaciones con `survives:`.
- pySigma aplica el pipeline **sobre el propio objeto de la regla** al convertir: convertir dos veces el mismo `SigmaCollection` repite las condiciones. `engine.load_rule` convierte una copia; hay un test que lo vigila.
- Security 4698/4702: la definición completa de la tarea va en XML dentro de `TaskContent` (4698) o `TaskContentNew` (4702), con `<Command>` literal y los `>` del contenido escapados como `&gt;`. Los indicadores se buscan en todo el XML.
- Anclas YAML (`&nombre` / `*nombre`) para reutilizar una lista de valores en dos campos dentro de la misma regla; pySigma las resuelve sin problema.
- `windash` expande `-` a `/`, `–`, `—`, `―`. En Splunk cada variante es un OR más (ver `splunk/win_powershell_encoded_command.spl`).
- Desfase conocido: los nombres de campo Sigma (`Provider_Name`) no siempre coinciden con los del add-on de Windows de Splunk. Se valida en la fase de Splunk real.

## Estado
- 2026-11-12: pipeline montado (validación, conversión a SPL, tests contra EVTX-ATTACK-SAMPLES, CI). Primera técnica completa: T1685.005 (dos reglas). Repo publicado con la CI en verde.
- 2026-11-12: T1059.001 PowerShell codificado (Image/OriginalFileName + abreviaturas de -EncodedCommand con windash; medium). Tests: 3 logs reales, 6 variantes inventadas, 4 benignos. Nuevo en los casos de test: `attack_events`.
- 2026-11-12: T1003.001 acceso a LSASS (Sysmon 10, máscaras de volcado conocidas, Defender excluido por ruta; high). 12 logs reales (10 volcados detectados; MalSeclogon = hueco conocido por 0x1410; `ps` de Meterpreter = descubrimiento, 0), 2 variantes, 4 benignos; 4 mutaciones cazadas. 55 tests.
- 2026-11-12: T1543.003 creación de servicio: dos reglas con la misma lógica (System 7045 y Sysmon 13 `ImagePath`) para `ImagePath` con intérpretes o carpetas de usuario; high. El mutation testing añadió la variante `cmd /c` y eliminó el indicador `\pipe\`. Huecos conocidos: `calc.exe`, AtomicService en carpeta no estándar; fuera de alcance: PsExec y driver vulnerable. 82 tests.
- 2026-11-12: T1053.005 tarea programada: dos reglas (Security 4698/4702 con el XML de la tarea; schtasks.exe `/create` o `/change` en Sysmon 1) con los indicadores de servicios; high. Benigno real: un DC actualizando sus tareas (4702). El mutation testing justificó el filtro de verbo y añadió `/change`.
- **2026-11-12: MVP COMPLETO.** 8 reglas, 5 técnicas, 110 tests (33 logs públicos, 22 variantes de ataque, 25 benignos). CI en verde. Siguiente según el ciclo: una semana de uso o repaso (Matt explica cada regla y el pipeline) y después iterar (mutation testing en la CI, Splunk en Docker, más reglas).
- 2026-11-12: *mutation testing* en la CI. Cada caso de test declara sus `mutations:` (43 en total; 4 supervivientes declaradas, las de `Provider_Name`) y `test_mutation_is_killed` exige que cada una la cace alguna comprobación. Nuevo comando `detlab mutate`. Hallazgos: el filtro `\ImagePath` de la regla de registro no tenía test (se añadió un benigno: la `Description` de un servicio) y pySigma modifica la regla al convertirla (corregido en el motor). 168 tests.
