/*
 * Copyright 2026 Ashish Thakur ashish.thakur1110@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.agnistack.omniflow.plugins.trivy;

import io.github.agnistack.omniflow.pluginapi.*;
import java.util.List;

/**
 * OmniFlow Plugin: Trivy Scan Report
 *
 * <p>Ingests Trivy JSON vulnerability scan reports and stores them as {@code BuildReport} records.
 * Each record includes:
 *
 * <ul>
 *   <li>Artifact metadata (name, type, OS family/name, image ID, repo tags)
 *   <li>All vulnerabilities from all scan results with severity, CVSS, CWE, fix info
 *   <li>All packages from all scan results with version, type, and license info
 *   <li>Computed severity counts (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN)
 *   <li>Fixable vulnerability count and vulnerable package count
 * </ul>
 *
 * Build:
 *
 * <pre>
 *   ./gradlew :omniflow-core-plugins:trivy-scan-report:jar
 * </pre>
 *
 * Upload:
 *
 * <pre>
 *   curl -X POST http://localhost:8080/api/plugins/upload \
 *        -F "file=@omniflow-core-plugins/trivy-scan-report/build/libs/trivy-scan-report-0.1.0.jar"
 * </pre>
 *
 * Ingest endpoint:
 *
 * <pre>
 *   POST http://localhost:8080/api/ingest/trivy-scan-report
 *   Content-Type: application/json
 *   Body: (Trivy JSON report)
 * </pre>
 */
public class TrivyScanReportPlugin implements OmniflowPlugin {

  @Override
  public PluginMetadata metadata() {
    return new PluginMetadata(
        "trivy-scan-report",
        "Trivy Scan Report",
        PluginMetadata.resolveVersion(TrivyScanReportPlugin.class, "0.1.0"),
        "Ingests Trivy vulnerability scan JSON reports: severity analytics, CVE tracking,"
            + " package inventory, and scan comparison. Includes an embedded vulnerability"
            + " dashboard micro UI.",
        "OmniFlow Security Analytics");
  }

  @Override
  public List<PluginIngestor<?>> ingestors() {
    return List.of(new TrivyScanReportIngestor());
  }

  @Override
  public boolean hasUi() {
    return true;
  }

  @Override
  public void onLoad(PluginContext ctx) {
    ctx.registerSchemaExtension(
        "BuildReport", "artifactName", "String", "Name of the scanned artifact (image, repo, etc.)");
    ctx.registerSchemaExtension(
        "BuildReport", "artifactType", "String", "Type of artifact: container_image, filesystem, repository");
    ctx.registerSchemaExtension(
        "BuildReport", "osFamily", "String", "OS family of the scanned image (e.g. redhat, debian, alpine)");
    ctx.registerSchemaExtension(
        "BuildReport", "osName", "String", "OS name and version (e.g. 9.5, 12.6)");
    ctx.registerSchemaExtension(
        "BuildReport",
        "vulnerabilities",
        "List",
        "All vulnerabilities found across all scan results");
    ctx.registerSchemaExtension(
        "BuildReport",
        "packages",
        "List",
        "All packages inventoried across all scan results");
    ctx.registerSchemaExtension(
        "BuildReport",
        "severityCounts",
        "Map",
        "Vulnerability counts by severity: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN");
    ctx.registerSchemaExtension(
        "BuildReport", "totalVulns", "Integer", "Total number of vulnerabilities found");
    ctx.registerSchemaExtension(
        "BuildReport", "fixableCount", "Integer", "Number of vulnerabilities with a known fix");
    ctx.registerSchemaExtension(
        "BuildReport", "packageCount", "Integer", "Total number of packages inventoried");
    ctx.registerSchemaExtension(
        "BuildReport",
        "vulnerablePackageCount",
        "Integer",
        "Number of packages with at least one vulnerability");
    ctx.log("Trivy Scan Report plugin loaded -> ingestor type: trivy-scan-report");
  }
}