# Trivy Scan Report — OmniFlow Plugin

OmniFlow plugin that ingests [Trivy](https://github.com/aquasecurity/trivy) JSON vulnerability scan reports and provides a dashboard UI for severity analytics, CVE tracking, package inventory, and scan-to-scan comparison.

<!-- TODO: add screenshot -->

## Features

- **Overview dashboard** with severity breakdown (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN), fixable-vulnerability counts, and artifact metadata
- **Vulnerability browser** with sortable columns for CVE ID, package, severity, CVSS score, installed vs. fixed version, and links to advisories
- **Package inventory** listing all packages found in the scan with version, architecture, type, and license information
- **Scan comparison** to diff vulnerability and package changes between two ingested reports
- **Dark mode** inherited from the OmniFlow host theme

## Quick Start

```bash
# 1. Build the plugin JAR (includes the embedded Next.js UI)
./gradlew jar

# 2. Upload to OmniFlow
curl -X POST http://localhost:8080/api/plugins/upload \
     -F "file=@build/libs/trivy-scan-report-0.1.0.jar"

# 3. Scan an image with Trivy
trivy image --format json -o report.json myregistry/myimage:latest

# 4. Ingest the report
curl -X POST http://localhost:8080/api/v1/ingest/trivy-scan-report \
     -H "Content-Type: application/json" \
     -d @report.json
```

The plugin UI is available in OmniFlow at the plugin's embedded UI route.

## Build

The Gradle build produces a fat JAR that bundles the Java ingestor, Jackson, and the statically exported Next.js UI:

```bash
./gradlew jar
```

The output JAR is written to `build/libs/trivy-scan-report-<version>.jar`.

To skip the UI build (useful when iterating on backend code only):

```bash
./gradlew jar -PskipUi=true
```

Requires Java 21. Node 22 and npm 10 are downloaded automatically by the Gradle Node plugin during a full build.

## Install

Upload the JAR to a running OmniFlow instance:

```bash
curl -X POST http://localhost:8080/api/plugins/upload \
     -F "file=@build/libs/trivy-scan-report-0.1.0.jar"
```

## Ingest

Generate a Trivy JSON report and POST it to the ingest endpoint:

```bash
# Generate the report
trivy image --format json -o report.json myregistry/myimage:latest

# Ingest into OmniFlow
curl -X POST http://localhost:8080/api/v1/ingest/trivy-scan-report \
     -H "Content-Type: application/json" \
     -d @report.json
```

The ingestor parses Trivy schema v2 JSON and extracts artifact metadata, all vulnerabilities (with CVSS scores, CWE IDs, fix versions), all packages (with licenses), and computed severity counts.

## UI Pages

| Page              | Path                | Description                                                                 |
|-------------------|---------------------|-----------------------------------------------------------------------------|
| **Overview**      | `/`                 | Summary cards with severity counts, fixable ratio, artifact info, and scan history |
| **Vulnerabilities** | `/vulnerabilities` | Searchable, sortable table of every CVE with severity, CVSS, and fix status |
| **Packages**      | `/packages`         | Full package inventory with version, type, architecture, and licenses       |
| **Compare**       | `/compare`          | Side-by-side diff of two scan reports showing added, removed, and changed vulnerabilities |

## Development

To run the UI locally against a running OmniFlow backend:

```bash
cd ui
npm install
npm run dev
```

The dev server starts on port 3002. Point it at your OmniFlow backend by setting:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev
```

## Release

Push a tag matching `v*` to trigger the GitHub Actions release workflow:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The workflow builds the fat JAR with the tag version and creates a GitHub Release with the artifact attached.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)