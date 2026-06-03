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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.agnistack.omniflow.pluginapi.PluginIngestor;
import io.github.agnistack.omniflow.pluginapi.SimplePluginDataRecord;
import java.io.InputStream;
import java.util.*;

/**
 * Parses a Trivy JSON vulnerability scan report into a {@code BuildReport} record.
 *
 * <p>Expected JSON structure (Trivy schema v2):
 *
 * <pre>
 * {
 *   "SchemaVersion": 2,
 *   "ArtifactName": "quay.io/jkube/jkube-java-11:latest",
 *   "ArtifactType": "container_image",
 *   "Metadata": {
 *     "OS": { "Family": "redhat", "Name": "9.5" },
 *     "ImageID": "sha256:...",
 *     "RepoTags": ["quay.io/jkube/jkube-java-11:latest"]
 *   },
 *   "Results": [
 *     {
 *       "Target": "...",
 *       "Class": "os-pkgs",
 *       "Type": "redhat",
 *       "Packages": [ { "Name": "...", "Version": "...", ... } ],
 *       "Vulnerabilities": [ { "VulnerabilityID": "CVE-...", ... } ]
 *     }
 *   ]
 * }
 * </pre>
 */
class TrivyScanReportIngestor implements PluginIngestor<SimplePluginDataRecord> {

  private static final ObjectMapper JSON = new ObjectMapper();

  @Override
  public String getType() {
    return "trivy-scan-report";
  }

  @Override
  public SimplePluginDataRecord ingest(InputStream data) throws Exception {
    JsonNode root = JSON.readTree(data);

    // ── Artifact metadata ──────────────────────────────────────────────────
    String artifactName = text(root, "ArtifactName", "unknown");
    String artifactType = text(root, "ArtifactType", "unknown");

    JsonNode metadata = root.path("Metadata");
    JsonNode osNode = metadata.path("OS");
    String osFamily = text(osNode, "Family", "");
    String osName = text(osNode, "Name", "");
    String imageId = text(metadata, "ImageID", "");

    List<String> repoTags = new ArrayList<>();
    metadata.path("RepoTags").forEach(t -> repoTags.add(t.asText()));

    // ── Iterate Results ────────────────────────────────────────────────────
    List<Map<String, Object>> allVulnerabilities = new ArrayList<>();
    List<Map<String, Object>> allPackages = new ArrayList<>();
    Set<String> vulnerablePackageNames = new HashSet<>();

    Map<String, Long> severityCounts = new LinkedHashMap<>();
    severityCounts.put("CRITICAL", 0L);
    severityCounts.put("HIGH", 0L);
    severityCounts.put("MEDIUM", 0L);
    severityCounts.put("LOW", 0L);
    severityCounts.put("UNKNOWN", 0L);

    long fixableCount = 0;

    JsonNode results = root.path("Results");
    if (results.isArray()) {
      for (JsonNode result : results) {
        String target = text(result, "Target", "");
        String resultClass = text(result, "Class", "");
        String resultType = text(result, "Type", "");

        // ── Packages ─────────────────────────────────────────────────────
        JsonNode pkgsNode = result.path("Packages");
        if (pkgsNode.isArray()) {
          for (JsonNode pkg : pkgsNode) {
            Map<String, Object> pkgMap = new LinkedHashMap<>();
            pkgMap.put("name", text(pkg, "Name", ""));
            String version = text(pkg, "Version", "");
            String release = text(pkg, "Release", "");
            pkgMap.put("version", release.isEmpty() ? version : version + "-" + release);
            pkgMap.put("arch", text(pkg, "Arch", ""));
            pkgMap.put("type", resultType);
            pkgMap.put("class", resultClass);
            pkgMap.put("target", target);

            List<String> licenses = new ArrayList<>();
            pkg.path("Licenses").forEach(l -> licenses.add(l.asText()));
            pkgMap.put("licenses", licenses);

            allPackages.add(pkgMap);
          }
        }

        // ── Vulnerabilities ──────────────────────────────────────────────
        JsonNode vulnsNode = result.path("Vulnerabilities");
        if (vulnsNode.isArray()) {
          for (JsonNode vuln : vulnsNode) {
            Map<String, Object> vulnMap = new LinkedHashMap<>();

            String vulnId = text(vuln, "VulnerabilityID", "");
            String pkgName = text(vuln, "PkgName", "");
            String severity = text(vuln, "Severity", "UNKNOWN").toUpperCase();
            String status = text(vuln, "Status", "affected");
            String installedVersion = text(vuln, "InstalledVersion", "");
            String fixedVersion = text(vuln, "FixedVersion", "");

            vulnMap.put("vulnId", vulnId);
            vulnMap.put("pkgName", pkgName);
            vulnMap.put("installedVersion", installedVersion);
            vulnMap.put("fixedVersion", fixedVersion);
            vulnMap.put("severity", severity);
            vulnMap.put("status", status);
            vulnMap.put("title", text(vuln, "Title", ""));
            vulnMap.put("description", text(vuln, "Description", ""));
            vulnMap.put("primaryUrl", text(vuln, "PrimaryURL", ""));
            vulnMap.put("publishedDate", text(vuln, "PublishedDate", ""));
            vulnMap.put("lastModifiedDate", text(vuln, "LastModifiedDate", ""));
            vulnMap.put("target", target);
            vulnMap.put("class", resultClass);
            vulnMap.put("type", resultType);

            // CVSS score
            JsonNode cvss = vuln.path("CVSS");
            double cvssScore = 0.0;
            if (cvss.isObject()) {
              // Try nvd first, then any available source
              JsonNode nvd = cvss.path("nvd");
              if (nvd.isObject()) {
                cvssScore = nvd.path("V3Score").asDouble(0.0);
              } else {
                Iterator<JsonNode> sources = cvss.elements();
                while (sources.hasNext()) {
                  JsonNode src = sources.next();
                  double score = src.path("V3Score").asDouble(0.0);
                  if (score > cvssScore) cvssScore = score;
                }
              }
            }
            vulnMap.put("cvssScore", cvssScore);

            // CWE IDs
            List<String> cweIds = new ArrayList<>();
            vuln.path("CweIDs").forEach(c -> cweIds.add(c.asText()));
            vulnMap.put("cweIds", cweIds);

            // References
            List<String> references = new ArrayList<>();
            vuln.path("References").forEach(r -> references.add(r.asText()));
            vulnMap.put("references", references);

            allVulnerabilities.add(vulnMap);

            // Track severity counts
            severityCounts.merge(severity, 1L, Long::sum);

            // Track fixable
            if (!fixedVersion.isEmpty()) {
              fixableCount++;
            }

            // Track vulnerable packages
            vulnerablePackageNames.add(pkgName);
          }
        }
      }
    }

    // ── Build the record ───────────────────────────────────────────────────
    Map<String, Object> fields = new LinkedHashMap<>();
    fields.put("projectName", artifactName);
    fields.put("artifactName", artifactName);
    fields.put("artifactType", artifactType);
    fields.put("osFamily", osFamily);
    fields.put("osName", osName);
    fields.put("imageId", imageId);
    fields.put("repoTags", repoTags);
    fields.put("vulnerabilities", allVulnerabilities);
    fields.put("packages", allPackages);
    fields.put("totalVulns", allVulnerabilities.size());
    fields.put("severityCounts", severityCounts);
    fields.put("fixableCount", fixableCount);
    fields.put("packageCount", allPackages.size());
    fields.put("vulnerablePackageCount", vulnerablePackageNames.size());
    fields.put("healthy", allVulnerabilities.isEmpty());

    return SimplePluginDataRecord.of("trivy-scan-report", fields);
  }

  private static String text(JsonNode node, String field, String fallback) {
    JsonNode v = node.path(field);
    return v.isMissingNode() || v.isNull() ? fallback : v.asText(fallback);
  }
}