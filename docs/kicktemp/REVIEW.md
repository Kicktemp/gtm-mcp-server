# Kicktemp Review: gtm-mcp-server v1.12.3

Stand: 2026-09-30, Basis: Upstream-Tag `v1.12.3` (`paolobietolini/gtm-mcp-server`), Branch `kicktemp/main`.
Alle Aussagen beziehen sich auf den Code vor unseren Änderungen. Status der Maßnahmen: siehe Spalte
„Maßnahme“ (H1–H9 = Härtungen aus `docs/kicktemp/SETUP.md`).

## 1. Netzwerk-Ziele

Es gibt **keine Telemetrie, keine Update-Checks, kein Analytics und kein Crash-Reporting** im Go-Code.
`mcp.gtmeditor.com` steht nur in `server.json`, `llms.txt`, README/ARCHITECTURE, Test-Fixtures und im
Deploy-Workflow, nie in einem Runtime-Call.

| Ziel | Wo | Bewertung |
|---|---|---|
| `tagmanager.googleapis.com` | `gtm/client.go:70` (`tagmanager.NewService`) | erlaubt |
| `oauth2.googleapis.com`, `accounts.google.com` | `auth/google.go` (`Exchange`, Refresh) | erlaubt, nur im OAuth-Modus |
| Service-Account-JWT-Exchange / ADC-Metadata-Server | `auth/service_account.go:16-30` | erlaubt (Google) |
| **Beliebige HTTPS-URLs (CIMD-Fetch)** | `auth/cimd.go:147-153`, ausgelöst durch unauthentifiziertes `/authorize` | **nicht erlaubt**. SSRF-Schutz vorhanden (Proxy aus, Private-IP-Block beim Dial, 64 KiB, 10 s), aber ausgehender Request an frei wählbare Hosts. Maßnahme: H4 schaltet `/authorize` im Default ab. |

Weitere URLs im Code sind Scope-Strings, ein Galerie-Link in einem Prompt (`gtm/prompts.go:520`) und Beispieltexte.

## 2. Secrets

| Punkt | Befund | Maßnahme |
|---|---|---|
| Bearer-Vergleich | `subtle.ConstantTimeCompare` (`auth/middleware.go:64`). **OK.** OAuth-Tokens werden per Map-Lookup gefunden (32 Byte `crypto/rand`), ebenfalls unkritisch. | – |
| Token/Key im Log | Bearer nur als sha256-Fingerprint (`auth/middleware.go:271`). API-Key und SA-JSON werden nirgends geloggt, nur `credential_source` (`main.go:137`). **OK.** | – |
| **`GTM_DEBUG`** | `gtm/client.go:19-68`: `loggingTransport` schreibt komplette Request- **und Response-Bodies** per stdlib-`log`. Header-Redaction ist regex-basiert und läuft vermutlich zu spät. Guard nur „`BASE_URL` enthält nicht localhost“. | H8: Dump entfernen |
| `LOG_LEVEL=debug` | Nur `debug` wird ausgewertet (`main.go:50`). Middleware loggt Methode, Tool, Dauer, Fehlerstring, **keine** Argumente/Ergebnisse (`middleware/logging.go`). GTM-API-Fehlerstrings werden ungefiltert geloggt. | H8: Test mit Log-Capture |
| Fehlermeldungen | `unauthorized()` gibt interne Texte an den Client (`auth/middleware.go:245-267`), z. B. „Token expired, refresh token also expired“. Kein Secret, nur Info-Leak. | akzeptiert |
| Log-Injection | `auth/handlers.go:185` loggt `error_description` aus der Query (angreiferkontrolliert). JSON-Handler, daher nur kosmetisch. | akzeptiert (OAuth im Default aus) |
| **Kein Auth (Open-Mode)** | Ohne OAuth-Client und ohne `SERVICE_ACCOUNT_API_KEY` bedient `/` das MCP **ohne Authentifizierung**, nur mit `logger.Warn` (`main.go:212-229`). | H4: Start bricht ab |
| API-Key-Stärke | Keine Mindestlänge für `SERVICE_ACCOUNT_API_KEY`. | H4: mindestens 32 Byte |
| Unbenutzte Config | `JWT_SECRET` und `GOOGLE_REDIRECT_URI` werden gelesen, aber nirgends verwendet (`config/config.go:73-74`). | nichts zu tun |
| Google-Identität | OAuth-Scopes enthalten weder `openid` noch `email` (`auth/google.go:19-25`). Jedes Google-Konto, das die Zustimmung durchläuft, bekommt ein Token. | H5 |
| Dynamic Client Registration | `/register` ist offen und unauthentifiziert (`auth/registration.go:33-100`). | H4: im Default 404 |
| Rate-Limiter | Bei 10 000 Besuchern werden **alle neuen IPs** abgelehnt (`middleware/ratelimit.go:56-58`). `/` (MCP) hat gar kein Rate-Limit. | akzeptiert (lokal, ein Client) |

## 3. Token-Store

`auth/file_token_store.go`, nur relevant, wenn `TOKEN_STORE_PATH` gesetzt ist:

- Verzeichnis: `os.MkdirAll(dir, 0o700)`. Bereits vorhandene Verzeichnisse behalten ihre Rechte.
- Datei: `CreateTemp` + `Chmod(0o600)` + `Sync` + `Rename`. **0600, OK.**
- Format: JSON `{"tokens":[TokenInfo…]}`, **Klartext** inklusive MCP-Access-/Refresh-Token und dem kompletten
  Google-`oauth2.Token` (also auch dem Google-Refresh-Token). Keine Verschlüsselung at rest.
- Im Service-Account-Betrieb (H4 Default) wird nichts persistiert. Im OAuth-Betrieb (Mittwald) muss das
  Volume `/data` daher als geheim behandelt werden.

## 4. Abhängigkeiten

Toolchain für die Analyse: `go1.26.0`. Vollständige Liste: Anhang A.

- `go mod verify`: **all modules verified**.
- `govulncheck ./...`:
  - **22 Schwachstellen in der Go-Standardbibliothek**, die im Code erreichbar sind. Alle sind ab
    **`go1.26.6`** behoben (`net/http`, `net/url`, `crypto/tls`, `crypto/x509`, `html/template`, `encoding/asn1`,
    `net/textproto`, `net`). Das betrifft den lokalen Compiler, nicht den Code. Der Docker-Build nutzt
    `golang:1.26-alpine` und muss auf einen Digest mit Go ≥ 1.26.6 gepinnt werden (siehe Abschnitt 5).
  - 7 Schwachstellen in importierten Paketen und 7 in Modulen, die der Code nicht aufruft. Darunter
    `golang.org/x/crypto@v0.55.0` (behoben in v0.56.0, eine ohne Fix). Maßnahme: `x/crypto` auf v0.56.0
    angehoben (erledigt, Abschnitt 9).
- Direkte Abhängigkeiten: `godotenv v1.5.1`, `go-sdk v1.7.0`, `uritemplate/v3 v3.0.2`, `oauth2 v0.36.0`,
  `x/time v0.15.0`, `google.golang.org/api v0.297.0`.

## 5. Dockerfile

| Punkt | Befund | Maßnahme |
|---|---|---|
| Base-Images | `mirror.gcr.io/library/golang:1.26-alpine@sha256:8ac98ca5…` (Digest bereits gepinnt) und `mirror.gcr.io/library/alpine:3.21` (**nicht gepinnt**) | Runtime auf `gcr.io/distroless/static:nonroot@sha256:…`, Builder neu pinnen |
| User | `adduser appuser`, `USER appuser`: **non-root, OK** | Distroless `nonroot` (UID 65532) |
| `/data` | `chmod 700`, Owner `appuser` | bleibt, mit `--chown=65532:65532` |
| Healthcheck | `wget` gegen `localhost:8080/health` | Distroless hat kein `wget`: eigenes `-healthcheck`-Flag im Binary |
| Listen-Adresse | Bindet immer an `:PORT` (alle Interfaces, `main.go:233`) | H7 |
| `.dockerignore` | `*.md` matcht in Docker-Semantik nur die Root-Ebene, `gtm/bestpractices/docs/*.md` bleibt also im Build-Kontext (Baseline-Build läuft durch, siehe Abschnitt 9). | ergänzen: `secrets/`, `docs/` |

## 6. CI / Workflows

| Datei | Befund | Maßnahme |
|---|---|---|
| `.github/workflows/release.yml` | Job `goreleaser` erzeugt GitHub-Releases auf den Tag. **Job `deploy` deployt per SSH/rsync auf den VPS des Autors** (`mcp.gtmeditor.com`, Secrets `SSH_PRIVATE_KEY`, `VPS_KNOWN_HOSTS`, `VPS_HOST`, `VPS_USER`, Environment `auto-deployment`). | **Datei entfernen** |
| `.github/workflows/security.yml` | govulncheck, gosec, staticcheck, Gitleaks, Trivy, CodeQL. Kein Deploy, nutzt nur `GITHUB_TOKEN`. | reduzieren auf Build + Test + `govulncheck` |
| `.github/dependabot.yml` | wöchentlich `gomod` und `github-actions`. | bleibt |

## 7. Tools (94 GTM-Tools + `ping`, `auth_status`)

Kategorien: **read**, **write**, **delete**, **publish**, **admin**, **code** (H9: führt eigenen Code aus).
Nicht klassifizierte Tools gelten als `admin`. Ein Test stellt sicher, dass jedes registrierte Tool
(`GTM_TOOL_GROUPS=all`) einen Eintrag hat.

`Scope`: `container` = Ziel ist `accountId`+`containerId`, `account` = nur `accountId`, `none` = kein Ziel.

| Tool | Kategorie | Scope | Datei |
|---|---|---|---|
| list_accounts | read | none | tool_accounts.go:30 |
| update_account | admin | account | tool_update_account.go:47 |
| list_containers | read | account | tool_containers.go:32 |
| lookup_container | read | none (Ergebnis wird gefiltert) | tool_inspection.go:74 |
| get_container_snippet | read | container | tool_inspection.go:96 |
| create_container | admin | account | tool_create_container.go:93 |
| update_container | admin | container | tool_update_container.go:48 |
| delete_container | admin | container | tool_delete_container.go:51 |
| list_workspaces | read | container | tool_workspaces.go:33 |
| get_workspace | read | container | tool_workspace_metadata.go:53 |
| quick_preview_workspace | read | container | tool_workspace_metadata.go:116 |
| get_workspace_status | read | container | tool_workspace_status.go:34 |
| create_workspace | write | container | tool_create_workspace.go:71 |
| update_workspace | write | container | tool_workspace_metadata.go:70 |
| delete_workspace | delete | container | tool_workspace_metadata.go:97 |
| list_versions | read | container | tool_list_versions.go:61 |
| get_latest_version_header | read | container | tool_get_latest_version_header.go:17 |
| get_version | read | container | tool_inspection.go:36 |
| get_live_version | read | container | tool_inspection.go:57 |
| create_version | write | container | tool_version.go:91 |
| update_version | write | container | tool_version_lifecycle.go:80 |
| undelete_version | write | container | tool_version_lifecycle.go:50 |
| delete_version | delete | container | tool_version_lifecycle.go:35 |
| publish_version | **publish** | container | tool_version.go:129 |
| set_latest_version | **publish** | container | tool_version_lifecycle.go:65 |
| list_tags, get_tag | read | container | tool_tags.go:44, :65 |
| create_tag, update_tag | write (**code** bei `type` = `html` oder `cvt_*`) | container | tool_create_tag.go:110, tool_update_tag.go:134 |
| delete_tag | delete | container | tool_delete_tag.go:58 |
| list_triggers, get_trigger | read | container | tool_triggers.go:34, tool_get_trigger.go:40 |
| create_trigger, update_trigger | write | container | tool_create_trigger.go:105, tool_update_trigger.go:126 |
| delete_trigger | delete | container | tool_delete_trigger.go:58 |
| list_variables, get_variable | read | container | tool_variables.go:34, tool_get_variable.go:40 |
| create_variable, update_variable | write (**code** bei `type` = `jsm`) | container | tool_create_variable.go:68, tool_update_variable.go:76 |
| delete_variable | delete | container | tool_delete_variable.go:58 |
| list_folders, get_folder, get_folder_entities | read | container | tool_folders.go:97, :124, :118 |
| create_folder, update_folder, move_entities_to_folder | write | container | tool_folders.go:136, :151, :184 |
| delete_folder, revert_folder | delete | container | tool_folders.go:169, :202 |
| revert_workspace_entity | delete | container | tool_reverts.go:25 |
| bulk_update_workspace | delete (Freitext-JSON, kann löschen; zusätzlich **code**-Prüfung) | container | tool_workspace_operations.go:47 |
| resolve_workspace_conflict | delete (kann Entitäten entfernen; zusätzlich **code**-Prüfung) | container | tool_workspace_operations.go:65 |
| sync_workspace | write | container | tool_workspace_operations.go:83 |
| list_zones, get_zone | read | container | tool_zones.go:69, :81 |
| create_zone, update_zone | write (Kind-Container per `publicId`) | container | tool_zones.go:96, :125 |
| delete_zone | delete | container | tool_zones.go:164 |
| list_environments, get_environment | read | container | tool_environments.go:66, :78 |
| create_environment, update_environment, reauthorize_environment | admin | container | tool_environments.go:93, :113, :137 |
| delete_environment | admin | container | tool_environments.go:155 |
| list_destinations, get_destination | read | container | tool_destinations.go:33, :45 |
| link_destination | admin | container | tool_destinations.go:63 |
| list_google_tag_configs, get_google_tag_config | read | container | tool_gtag_configs.go:54, :66 |
| create_google_tag_config, update_google_tag_config | write | container | tool_gtag_configs.go:81, :105 |
| delete_google_tag_config | delete | container | tool_gtag_configs.go:134 |
| combine_containers | admin (zweiter Container `sourceContainerId`) | container | tool_container_admin.go:36 |
| move_tag_id | admin | container | tool_container_admin.go:60 |
| list_built_in_variables | read | container | tool_built_in_variables.go:38 |
| enable_built_in_variables | write | container | tool_built_in_variables.go:82 |
| disable_built_in_variables | delete | container | tool_built_in_variables.go:131 |
| list_templates, get_template | read | container | tool_list_templates.go:86, tool_get_template.go:77 |
| create_template, update_template, import_gallery_template | **code** | container | tool_create_template.go:69, tool_update_template.go:94, tool_import_gallery_template.go:84 |
| delete_template | delete | container | tool_delete_template.go:57 |
| list_clients, get_client | read | container | tool_clients.go:37, :71 |
| create_client, update_client | write | container | tool_create_client.go:68, tool_update_client.go:76 |
| delete_client | delete | container | tool_delete_client.go:56 |
| list_transformations, get_transformation | read | container | tool_transformations.go:37, :71 |
| create_transformation, update_transformation | write | container | tool_create_transformation.go:66, tool_update_transformation.go:74 |
| delete_transformation | delete | container | tool_delete_transformation.go:56 |
| get_tag_templates, get_trigger_templates | read | none | tool_templates.go:32, :57 |
| ping, auth_status | read | none | main.go:302, :320 |

Zusätzlich zu Tools adressieren auch **Resources** (`gtm://accounts/{a}/containers/{c}/workspaces/{w}/tags|triggers|variables`,
`gtm/resources.go:39-103`) und **Prompts** (`audit_container`, `generate_tracking_plan`) Container. Die
Allowlist (H2) prüft `resources/read` mit.

Es gibt keine Tools für User-Permissions (`allowUserPermissionFeatureUpdate` wird bewusst nie gesendet).

## 8. Zusätzliche GTM-API-Calls durch die Kicktemp-Schicht (Quotas)

Die Container-Allowlist (H2) benötigt pro Call **keine** GTM-Requests; sie prüft gegen eine beim Start
aufgebaute Map. `fingerprint_before` (H3) und der Typ-Check (H9) nutzen einen In-Memory-Cache aus früheren
`get_*`/`list_*`/`create_*`/`update_*`-Ergebnissen.

| Situation | Zusätzliche API-Calls |
|---|---|
| Start (Allowlist-Map) | 1 `accounts.list` + 1 `containers.list` pro Account |
| read-Tools | 0 |
| write/delete/code-Tool, Entität im Cache | 0 |
| write/delete/code-Tool, Cache-Miss (update/delete) | 1 GET der Entität |
| create-Tools | 0 (`fingerprint_before` ist leer) |

Die Werte gelten so wie implementiert und sind durch Tests belegt (`TestAllowlistNoExtraRequestsPerCall`,
`TestAuditFingerprintBeforeFetchesOnlyOnCacheMiss`). Zusätzlich:

- Bei leerem `KT_ALLOWED_CONTAINERS` und bei `*` entstehen beim Start keine GTM-Requests.
- Der Cache gilt 10 Minuten; danach kostet das nächste `update_*`/`delete_*` auf dieselbe Entität wieder
  einen GET.
- Die Typ-Prüfung des Code-Gates (`update_tag`/`update_variable` ohne `type`-Argument) nutzt denselben
  Cache und kostet höchstens denselben einen GET, nur wenn `KT_ALLOW_CUSTOM_CODE=false` ist.
- Im OAuth-Modus ohne Service Account (Mittwald) wird die Container-Zuordnung beim ersten Aufruf gebaut
  (1 + Anzahl Accounts) und höchstens alle 5 Minuten neu geladen, wenn eine unbekannte Container-ID
  angefragt wird.

## 9. Ergebnisse nach Implementierung

**Stand der Maßnahmen** (ein Commit je Punkt auf `kicktemp/main`):

| Punkt | Maßnahme | Ergebnis |
|---|---|---|
| Review | dieses Dokument, `.gitignore`-Ausnahmen | erledigt |
| H1 | Tool-Gating Publish/Delete/Admin | erledigt, getestet |
| H2 | Container-Allowlist (`*` = alle, leer = nichts), ID-Prüfung gegen Pfad-Traversal | erledigt, getestet |
| H3 | Audit-Log (start/end/denied, `args`, Fingerprints) | erledigt, getestet |
| H4 | OAuth aus, kein Open-Mode, Route-Guard, Key ≥ 32 Byte | erledigt, getestet |
| H5 | `KT_ALLOWED_EMAILS` (id_token-Prüfung im Callback, Prüfung pro Request) | erledigt, getestet (mit gefaktem id_token; kein echter Google-Login) |
| H6 | SA-Key aus Datei | erledigt, getestet |
| H7 | Listen-Adresse, `-healthcheck` | erledigt, getestet |
| H8 | `GTM_DEBUG`-Body-Dump entfernt, Log-Leak-Tests | erledigt, Regressionstest schlägt auf altem Code fehl |
| H9 | Code-Gate (`KT_ALLOW_CUSTOM_CODE`) | erledigt, getestet |
| H10 | Rate-Limiter `KT_GTM_QPM` (gleitendes Fenster), `api_calls` im Audit-Log | erledigt, getestet mit Fake-Clock |
| Docker | distroless nonroot, Digests gepinnt, Compose | erledigt, Image gebaut und geprüft |
| CI | `release.yml` (SSH-Deploy) und `security.yml` gelöscht, `ci.yml` neu | erledigt, **noch nicht auf GitHub gelaufen** |

**Prüfergebnisse**

- `go test ./...`: alle Pakete grün, auch mit `-race` (`internal/kicktemp`, Root-Paket) und auf Go 1.26.8.
- Docker-Baseline (`docker build .` auf v1.12.3): erfolgreich. Die Vermutung „`.dockerignore` bricht das
  `go:embed`“ hat sich nicht bestätigt (`*.md` matcht nur auf Root-Ebene).
- `govulncheck ./...` mit **Go 1.26.8** (Toolchain des Builder-Images): **0 betroffene Schwachstellen**.
  Übrig bleibt `GO-2026-5932` (`x/crypto/openpgp`, kein Fix verfügbar); das Paket wird nicht aufgerufen.
  Mit dem lokalen Go 1.26.0 zeigt `govulncheck` weiter die 22 Standardbibliotheks-Meldungen aus Abschnitt 4,
  weil dieser Compiler veraltet ist (nicht der Code).
- Laufendes Image (`docker compose up`, Fake-Service-Account ohne Google-Zugang):
  - Status `healthy`, User `65532:65532`, `ReadonlyRootfs=true`, `CapDrop=ALL`
  - Port nur `127.0.0.1:8080`
  - `/health` 200, ohne oder mit falschem Bearer 401, `/authorize` und `/register` 404
  - `tools/list`: 49 Tools, kein `publish_*`, kein `delete_*`, kein `combine_containers`
  - `audit.jsonl`: Modus 0600, Owner 65532
- Nicht geprüft, weil ein echter Service Account nötig ist: die Schritte aus `SETUP.md` Abschnitt 5, zweiter
  Teil (GTM lesen/schreiben, Publish scheitert an GTM-Rechten, Audit-Zeilen mit echten Fingerprints).

**Offene Punkte / Restrisiken:** siehe `SETUP.md` Abschnitt 7.

## Anhang A: `go list -m all` (Stand v1.12.3)

```
gtm-mcp-server
cel.dev/expr v0.25.2
cloud.google.com/go v0.112.2
cloud.google.com/go/auth v0.23.2
cloud.google.com/go/auth/oauth2adapt v0.2.8
cloud.google.com/go/compute/metadata v0.9.0
cloud.google.com/go/longrunning v0.5.6
cloud.google.com/go/translate v1.10.3
github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.33.0
github.com/cespare/xxhash/v2 v2.3.0
github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2
github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
github.com/envoyproxy/go-control-plane v0.14.0
github.com/envoyproxy/go-control-plane/envoy v1.37.0
github.com/envoyproxy/go-control-plane/ratelimit v0.1.0
github.com/envoyproxy/protoc-gen-validate v1.3.3
github.com/felixge/httpsnoop v1.1.0
github.com/go-jose/go-jose/v4 v4.1.4
github.com/go-logr/logr v1.4.4
github.com/go-logr/stdr v1.2.2
github.com/golang-jwt/jwt/v5 v5.3.1
github.com/golang/glog v1.2.5
github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da
github.com/golang/protobuf v1.5.4
github.com/google/go-cmp v0.7.0
github.com/google/go-pkcs11 v0.3.0
github.com/google/jsonschema-go v0.4.3
github.com/google/s2a-go v0.1.9
github.com/google/uuid v1.6.0
github.com/googleapis/enterprise-certificate-proxy v0.3.20
github.com/googleapis/gax-go/v2 v2.24.0
github.com/joho/godotenv v1.5.1
github.com/kr/pretty v0.3.1
github.com/kr/text v0.2.0
github.com/modelcontextprotocol/go-sdk v1.7.0
github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10
github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2
github.com/rogpeppe/go-internal v1.14.1
github.com/segmentio/asm v1.2.1
github.com/segmentio/encoding v0.5.4
github.com/spiffe/go-spiffe/v2 v2.7.0
github.com/stretchr/testify v1.11.1
github.com/yosida95/uritemplate/v3 v3.0.2
go.opencensus.io v0.24.0
go.opentelemetry.io/auto/sdk v1.2.1
go.opentelemetry.io/contrib/detectors/gcp v1.44.0
go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.67.0
go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.69.0
go.opentelemetry.io/otel v1.44.0
go.opentelemetry.io/otel/metric v1.44.0
go.opentelemetry.io/otel/sdk v1.44.0
go.opentelemetry.io/otel/sdk/metric v1.44.0
go.opentelemetry.io/otel/trace v1.44.0
golang.org/x/crypto v0.55.0
golang.org/x/mod v0.38.0
golang.org/x/net v0.58.0
golang.org/x/oauth2 v0.36.0
golang.org/x/sync v0.22.0
golang.org/x/sys v0.47.0
golang.org/x/term v0.45.0
golang.org/x/text v0.41.0
golang.org/x/time v0.15.0
golang.org/x/tools v0.48.0
gonum.org/v1/gonum v0.17.0
google.golang.org/api v0.297.0
google.golang.org/appengine v1.6.8
google.golang.org/genproto v0.0.0-20260715232425-e75dac1f907d
google.golang.org/genproto/googleapis/api v0.0.0-20260715232425-e75dac1f907d
google.golang.org/genproto/googleapis/bytestream v0.0.0-20260819154853-08b0e4226688
google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688
google.golang.org/grpc v1.83.2
google.golang.org/protobuf v1.36.12
gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
gopkg.in/yaml.v3 v3.0.1
```
