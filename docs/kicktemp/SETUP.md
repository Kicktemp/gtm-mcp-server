# Kicktemp GTM MCP Server: Setup und Betrieb

Fork von `paolobietolini/gtm-mcp-server` (BSD-3, Basis `v1.12.3`). Läuft lokal in Docker, spricht nur mit
Google (`tagmanager.googleapis.com`, `oauth2.googleapis.com`, `accounts.google.com`). Nichts läuft über
`mcp.gtmeditor.com`. Befunde der Code-Prüfung: [REVIEW.md](REVIEW.md).

## 1. Was der Fork anders macht

Alle Änderungen liegen in `internal/kicktemp/`; Upstream-Dateien haben nur kleine Hooks (`main.go`,
`auth/handlers.go`, `gtm/client.go`, `gtm/kicktemp_hooks.go`).

| Env-Variable | Default | Wirkung |
|---|---|---|
| `SERVICE_ACCOUNT_API_KEY` | – (Pflicht) | Bearer-Key für den MCP-Endpoint, mindestens 32 Byte (`openssl rand -hex 32`). Ohne Key startet der Server nicht; einen offenen Modus gibt es nicht mehr. |
| `KT_ALLOW_PUBLISH` | `false` | `publish_version`, `set_latest_version` |
| `KT_ALLOW_DELETE` | `false` | alle `delete_*`, `revert_*`, `disable_built_in_variables`, `bulk_update_workspace`, `resolve_workspace_conflict` |
| `KT_ALLOW_ADMIN` | `false` | Container/Account ändern oder löschen, `combine_containers`, `move_tag_id`, `link_destination`, Environments anlegen/ändern/löschen |
| `KT_ALLOW_CUSTOM_CODE` | `false` | Templates (`create_template`, `update_template`, `import_gallery_template`), Tags vom Typ `html` oder `cvt_*`, Variablen vom Typ `jsm`. Geprüft wird auf den Argumenten (auch in `changesJson`/`entityJson`) und bei Updates auf dem bestehenden Typ. |
| `KT_ALLOWED_CONTAINERS` | leer = **nichts** erlaubt | Kommagetrennte Public IDs (`GTM-XXXX`), oder `*` für alle. Wird beim Start einmal zu Account/Container-IDs aufgelöst; eine unbekannte ID bricht den Start ab. |
| `KT_AUDIT_LOG_PATH` | `/data/audit.jsonl` | Audit-Log (JSON Lines, 0600). Nicht abschaltbar; ist die Datei nicht beschreibbar, startet der Server nicht. |
| `KT_OAUTH_ENABLED` | `false` | Aus: keine OAuth-Routen, Google-Client-Variablen werden ignoriert. |
| `KT_ALLOWED_EMAILS` | leer | Nur bei OAuth: erlaubte Google-Konten. OAuth ohne diese Liste startet nicht. |
| `GOOGLE_SERVICE_ACCOUNT_KEY_FILE` | – | Pfad zum SA-Key (Docker Secret). Nicht zusammen mit `GOOGLE_SERVICE_ACCOUNT_KEY_JSON`. |
| `KT_LISTEN_ADDR` | `127.0.0.1:8080` | Im Container `0.0.0.0:8080` (Dockerfile), der Port wird nur auf `127.0.0.1` veröffentlicht. |

Zusätzlich:

- Erreichbar sind nur `/health` (ohne Auth) und `/` (der MCP-Endpoint, Bearer). Alle anderen Pfade
  liefern 404, auch `/mcp`, `/llms.txt` und die OAuth-Routen (bei `KT_OAUTH_ENABLED=false`).
- `GTM_DEBUG` (HTTP-Body-Dump) wurde entfernt.
- Bei jedem Tool-Aufruf werden ID-Argumente (`*Id`, `*Ids`) auf `[A-Za-z0-9_-]` geprüft, weil Upstream sie
  ungeprüft in API-Pfade einsetzt (`workspaceId="5/../../containers/9"`).

### Audit-Log

Pro nicht-lesendem Tool-Aufruf zwei Zeilen mit gleicher `call_id`:

- `start`: vor dem Aufruf. Enthält Tool, Kategorie, Account, Container, `publicId`, Workspace, Entität,
  `fingerprint_before`, `identity` und `args` (Secrets als `[redacted]`, maximal 16 KB, sonst
  `args_truncated`). Kann die Zeile nicht geschrieben werden, wird der Aufruf abgelehnt.
- `end`: `result` (`ok`/`error`), `fingerprint_after`, Fehlertext.

Abgelehnte Aufrufe erzeugen eine `denied`-Zeile. `identity` ist `service-account`, `email:<konto>` (OAuth)
oder ein Token-Fingerprint.

```bash
# Log lesen (der Container hat keine Shell)
docker run --rm -v gtm-mcp-server_gtm-data:/data alpine:3.21 cat /data/audit.jsonl | tail -20
```

## 2. Google-Seite (einmalig)

1. GCP-Projekt „kicktemp-gtm-mcp“ anlegen, **Tag Manager API** aktivieren.
2. Service Account anlegen, JSON-Key erzeugen und als `secrets/gtm-sa.json` ablegen (`secrets/` ist in
   `.gitignore` und `.dockerignore`).
3. In GTM die E-Mail des Service Accounts hinzufügen:
   - Konto: **Lesen** (Admin ist nicht nötig)
   - Container: **Bearbeiten** (nicht „Genehmigen“, nicht „Veröffentlichen“)
   - nur Container eintragen, an denen gearbeitet wird
4. Test-Container „Kicktemp Sandbox“ anlegen und dem Service Account zuweisen.

Zwei Sicherheitsnetze sind unabhängig voneinander: der Server registriert keine Publish-Tools, und der
Service Account darf in GTM nicht veröffentlichen.

## 3. Lokal starten

```bash
cp .env.example .env
# SERVICE_ACCOUNT_API_KEY=$(openssl rand -hex 32) in .env eintragen
# KT_ALLOWED_CONTAINERS=GTM-XXXX in .env eintragen (Public ID der Sandbox)
docker compose up -d --build
docker compose ps          # Status "healthy"
docker compose logs -f
```

Nach Änderungen an der Container-Liste in GTM oder in `KT_ALLOWED_CONTAINERS`: `docker compose up -d`
(Neustart). Die Zuordnung Public ID → Container-ID wird nur beim Start gelesen.

## 4. In Claude einbinden

Endpoint ist `http://localhost:8080/` (Pfad `/`), Header `Authorization: Bearer <SERVICE_ACCOUNT_API_KEY>`.

**Claude Code**

```bash
claude mcp add --transport http --scope user gtm-mcp http://localhost:8080/ \
  --header "Authorization: Bearer <SERVICE_ACCOUNT_API_KEY>"
```

**Claude Desktop-App**: `~/Library/Application Support/Claude/claude_desktop_config.json`, in
`mcpServers` neben `google-ads-mcp`, `analytics-mcp` und `kickmobimed-mcp`. Das Muster ist dasselbe wie
bei `kickmobimed-mcp` (Remote-Server über `mcp-remote`, Secret in `env`, nicht in `args`):

```json
"gtm-mcp": {
  "command": "/opt/homebrew/bin/npx",
  "args": [
    "-y",
    "mcp-remote",
    "http://localhost:8080/",
    "--header",
    "Authorization:${GTM_MCP_AUTH}"
  ],
  "env": {
    "GTM_MCP_AUTH": "Bearer <SERVICE_ACCOUNT_API_KEY>",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
  }
}
```

Der Wert „Bearer …“ steht absichtlich komplett in `env`: Leerzeichen in `args` werden von manchen
`mcp-remote`-Versionen falsch übergeben. Danach die Desktop-App neu starten. Der Server muss laufen
(`docker compose up -d`), sonst zeigt Claude den Connector als getrennt an.

## 5. Abnahme (gegen den Sandbox-Container)

Bereits ohne Google-Zugang geprüft (laufendes Docker-Image bzw. der lokal gebaute Binary desselben Codes):

- [x] Container läuft als `65532:65532`, Root-Dateisystem read-only, `cap_drop: ALL`, Port nur auf `127.0.0.1`
- [x] Ohne oder mit falschem Bearer → 401; `/authorize`, `/register`, `/token`, `/llms.txt` → 404; `/health` → 200
- [x] `tools/list` enthält kein `publish_version`, kein `delete_*`, kein `combine_containers`, keine Template-Tools
- [x] Aufruf auf einen Container außerhalb von `KT_ALLOWED_CONTAINERS` wird abgelehnt und im Audit-Log als `denied` vermerkt
- [x] `LOG_LEVEL=debug`: keine Tokens, Keys oder SA-Inhalte im Log (Tests `TestDebugLogsContain…`, `TestGTMDebug…`)
- [x] `audit.jsonl` hat Modus 0600 und gehört UID 65532

Braucht den echten Service Account, von Niels zu prüfen:

- [ ] Container, Workspaces, Tags, Trigger, Variablen lesen
- [ ] Tag im Workspace anlegen (z. B. GA4-Event), ändern, `create_version` ausführen
- [ ] Publish-Tool ist nicht vorhanden; ein direkter API-Publish mit dem SA scheitert an den GTM-Rechten
- [ ] Container außerhalb der Liste (echte zweite Container-ID) wird abgelehnt
- [ ] `audit.jsonl` enthält `start` und `end` für jede Schreibaktion, mit `fingerprint_before`/`_after`
- [ ] Custom-HTML-Tag anlegen wird abgelehnt (`KT_ALLOW_CUSTOM_CODE=false`)
- [ ] Beim Start mit falscher Public ID in `KT_ALLOWED_CONTAINERS`: Abbruch mit Fehlermeldung

## 6. Upstream-Updates

Nur auf neue Release-Tags rebasen, nicht auf `main`.

```bash
git fetch upstream --tags
git switch kicktemp/main
git rebase --onto <NEUER_TAG> <ALTER_TAG> kicktemp/main   # aktuell ALTER_TAG=v1.12.3
go test ./...
```

- `TestEveryRegisteredToolIsClassified` schlägt an, wenn Upstream neue Tools einführt. Sie in
  `internal/kicktemp/categories.go` einordnen (bis dahin gelten sie als `admin`, sind also aus) und den
  erwarteten Zähler (94) im Test anheben.
- `release.yml` und `security.yml` sind bei uns gelöscht. Ändert Upstream sie, gibt es einen
  modify/delete-Konflikt: gelöscht lassen.
- Neue Upstream-Stellen, die ausgehende HTTP-Calls machen, in [REVIEW.md](REVIEW.md) Abschnitt 1 prüfen.

## 7. Bekannte Grenzen

- Die Container-Zuordnung wird beim Start gelesen. Neue Container erfordern einen Neustart.
- Der Fingerprint-Cache (`fingerprint_before`, Typ-Prüfung) gilt 10 Minuten. Änderungen außerhalb dieses
  Servers (GTM-Oberfläche) können dazu führen, dass `fingerprint_before` veraltet ist.
- Der Code-Gate deckt `html`, `cvt_*` (Tags), `jsm` (Variablen) und Templates ab. Custom-Template-Variablen,
  Clients und Transformations vom Typ `cvt_*` sind nicht gesperrt.
- `link_destination`: die Quelle der Destination wird nicht gegen die Allowlist geprüft. Das Tool ist
  Admin-only.
- Prompts (`audit_container`, `generate_tracking_plan`) sind nicht gesperrt. Sie rufen die API nicht selbst
  auf; die Tool-Aufrufe danach laufen durch die Allowlist.
- Im OAuth-Modus liegen Google-Refresh-Tokens im Klartext in `TOKEN_STORE_PATH`. Das Volume ist dann geheim
  zu halten.
- Ein OAuth-Modus ohne Service Account baut die Container-Zuordnung beim ersten Aufruf mit den Rechten des
  Anmeldenden auf und lädt höchstens alle 5 Minuten neu.

## 8. Mittwald (später, optional)

Nur nötig, wenn der Server ohne laufenden Mac erreichbar sein muss. Dann öffentlich, also:

- HTTPS über Mittwald, H1–H5 zwingend, starker Bearer-Key, wenn möglich IP-Allowlist.
- Als Connector in claude.ai wird voraussichtlich OAuth gebraucht: `KT_OAUTH_ENABLED=true`,
  `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`, `KT_ALLOWED_EMAILS`, `BASE_URL=https://…`,
  `TRUST_PROXY=true` hinter dem Proxy. In diesem Modus sind zusätzlich `/authorize`, `/token`,
  `/register`, `/oauth/callback` und `/.well-known/*` erreichbar (Registrierung ist offen, aber ohne
  erlaubtes Google-Konto entsteht kein Token).
- Vorher klären: Container-Hosting (Verfügbarkeit), Secrets-Handling, persistentes Volume für `/data`.
