# Матрица контролей безопасности

Центральный справочник контролей DevSecOps CI/CD.

## Сводная матрица

| Контроль | Secure SDLC | SDLC-точка | Что сканируем | DAF | JCSF | Шаблон job | Статус |
|----------|-------------|------------|---------------|-----|------|-------------|--------|
| **Linters** | Code | IDE, MR | Style + security rules | `T-DEV-SRC` | — | custom / Code-Quality | baseline |
| **SAST** | Code, Test | IDE, MR, nightly | Исходный код | `T-CODE-SST` | — | `jobs/sast.*` | baseline |
| **Secret scan** | Code | SCM, MR | Код, IaC | `T-CODE-SECDN` | — | `jobs/secret-scan.*` | baseline |
| **OSA** | Code | MR | Манифесты зависимостей | `T-CODE-SC` | — | `jobs/osa.*` | B3 · offline KEV/EPSS |
| **SCA** | Build | main post-SBOM | Образ контейнера | `T-CODE-SC`, `T-CODE-IMG` | `img` | `jobs/container-scan.*`, `oss/trivy-sca` | C2 · offline KEV/EPSS |
| **IaC scan** | Code, Test | MR, pre-deploy | tf, k8s, helm | `T-PREPROD-MANSEC` | `man` | `jobs/iac-scan.*` | baseline |
| **Dockerfile** | Build | MR (paths) | Dockerfile | `T-CODE-DOCKERFS` | `Dock` | `jobs/dockerfile-lint.*` | baseline |
| **SBOM** | Build | Build | CycloneDX | `T-ADI-ART-3-1` | — | `jobs/sbom.*` | C1 |
| **Signing** | Release | Build | cosign | `T-ADI-ART-4-*` | — | `jobs/sign.*` | C4 |
| **DAST** | Test | Preprod | Web/API | `T-PREPROD-DAST` | — | `jobs/dast.*` | D1 |
| **Fuzzing (API)** | Test | QA / Preprod | OpenAPI/API | финтех | — | `jobs/api-fuzz-schemathesis.*` | D1 API |
| **Fuzzing (binary)** | Test | QA | C/Go/JVM | финтех | — | `jobs/binary-fuzz.*` | QA |
| **Sec func tests** | Test | Preprod | Auth, headers | `T-PREPROD-SECTEST` | — | `jobs/sec-func-tests.*` | D2 |
| **IAST** | Test | Preprod | Runtime app | финтех | — | `jobs/iast-preprod.*` | F1 implemented (OSS ZAP full) |
| **ASTO** | All | Все этапы | SARIF агрегация | `P-DEFECT-CNS` | — | `jobs/aspm/*`, `aspm-export.py` | oss-full |
| **WAF/API** | Deploy, Operate | Prod edge | L7, API | `T-PROD-NETWORK` | Gen L4/L7 | runbook F2 | out-of-CI |
| **RASP** | Deploy, Operate | Prod runtime | Атаки в app | `T-PROD-EVENTS` | `cont` | runbook F2 | out-of-CI |
| **K8s admission** | Deploy | Prod deploy | Pods, policies | `T-PROD-RUN` | `orchr` | `k8s/admission/` | E1 |
| **Network policy** | Deploy | Prod | L4 pod traffic | `T-PROD-NETWORK` | `gen` | `k8s/network/` | E2 |
| **CWPP/Falco** | Operate | Prod | Syscalls, exec | `T-PROD-EVENTS` | `cont` | `k8s/runtime/` | E3 |
| **Taint analysis** | Plan | Design | Поверхность атаки | `P-REQ-TM` | — | SecChamp tool | design |
| **SBOM monitor** | Monitor | Continuous | CVE on deps | `T-ADI-DEP` | — | F3 runbook | F3 |
| **Misuse/Abuse cases** | Plan | Design | Threat model | `P-REQ-TM-4-1` | — | governance checklist | gap |
| **Config Drift (runtime)** | Build, Release | Cluster | Live vs Git | `T-PREPROD-MANSEC` | `man` | E1 Kyverno + drift runbook | partial |
| **Performance testing** | Test | QA/UAT | Load, latency | финтех | — | doc / optional | gap |
| **Chaos / Resilience** | Operate | Prod | Fault injection | DSOMM | — | [F4-resilience.md](phases/F4-resilience.md) | gap |
| **PKI** | Deploy | Cluster | Certs, rotation | `T-PROD-NETWORK` | `orchr` | [runbooks/pki-k8s.md](runbooks/pki-k8s.md) | gap |
| **IDS** | Deploy, Operate | Network | Intrusion detect | `T-PROD-EVENTS` | `gen` | Falco/SIEM partial | partial |
| **Skill scan** | Code | MR | Agent skills | Cisco AI | — | `jobs/skill-scanner.*` | AI1 optional |
| **MCP scan** | Code | MR | MCP configs | Cisco AI | — | `jobs/mcp-scan.*` | AI1 optional |
| **ML data PII** | Code | MR | datasets | `T-MLDATA-DT-4-1` | — | `jobs/ml-data-scan.*` | ML1 block |
| **ML-BOM** | Build | main | models/data | `T-ADI-ART-ML-3-3` | — | `jobs/ml-bom.*` | ML2 optional |
| **AI BOM** | Build | main | AI stack | Cisco | — | `jobs/aibom.*` | AI2 optional |
| **Pickle scan** | Build | MR | pickle files | Cisco | — | `jobs/pickle-scan.*` | AI2 optional |

## Уровни внедрения

| Уровень | Описание |
|---------|----------|
| **Минимум** | B1–B3 warn; SCM hardening A1 |
| **Рекомендуется** | B1–B5 block critical/high; C1–C2; D1; ASTO triage |
| **Продвинутый** | C4 signing; E1–E4; F1–F3; fuzzing в QA |

## Политика gates

Единый файл: [config/security-gate-policy.yaml](../config/security-gate-policy.yaml).

| Severity | MR default | main default |
|----------|------------|--------------|
| critical | block | block |
| high | block | block |
| medium | warn | warn |
| low | info | info |

## Управление дефектами (ASTO)

| Практика | Реализация |
|----------|------------|
| `P-DEFECT-MNG` | SLA в трекере, SecChamp triage |
| `P-DEFECT-CNS` | SARIF → DefectDojo via `scripts/aspm-export.py` per scan job |
| Размеченный SAST | SecChamp помечает false positive до merge |

## Ignore-файлы

Контроль обхода сканеров (`T-DEV-SRC-3-6`):

- Изменения `.semgrepignore`, `.gitleaksignore`, `.trivyignore` — review SecChamp + CODEOWNERS.
- Запрет silent skip без тикета.

## Инструменты

См. [04-tooling-catalog.md](04-tooling-catalog.md).

## IAST / RASP / WAF

Не выделены отдельными поддоменами DAF — **расширение из финтех-процесса**, маппинг:

- IAST → `T-PREPROD-DAST-3-3` (бизнес-логика в тестах)
- RASP → `T-PROD-EVENTS-3-1`, JCSF **cont**
- WAF → `T-PROD-NETWORK-2-2`

Runbooks: [phases/F2-rasp-waf.md](phases/F2-rasp-waf.md).
