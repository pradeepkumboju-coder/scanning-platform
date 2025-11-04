#!/usr/bin/env node

// generate-html-report.js - Generate human-readable HTML security report
const fs = require('fs');
const path = require('path');
const { program } = require('commander');

program
  .option('--scan-id <id>', 'Scan ID')
  .option('--input-dir <dir>', 'Input directory with JSON reports')
  .option('--output-file <file>', 'Output HTML file path')
  .parse();

const { scanId, inputDir, outputFile } = program.opts();

// Severity levels and colors
const SEVERITY_COLORS = {
  critical: '#dc3545',
  high: '#fd7e14',
  moderate: '#ffc107',
  medium: '#ffc107',
  low: '#28a745',
  info: '#17a2b8'
};

const SEVERITY_ORDER = ['critical', 'high', 'moderate', 'medium', 'low', 'info'];

// Load JSON report files
function loadJsonReport(filename) {
  const filePath = path.join(inputDir, 'json', filename);
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
  } catch (error) {
    console.warn(`Failed to load ${filename}: ${error.message}`);
  }
  return null;
}

// Load text report files
function loadTextReport(filename) {
  const filePath = path.join(inputDir, 'raw', filename);
  try {
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath, 'utf8');
    }
  } catch (error) {
    console.warn(`Failed to load ${filename}: ${error.message}`);
  }
  return null;
}

// Parse npm audit results for display
function parseNpmAuditForDisplay(auditData) {
  if (!auditData || !auditData.vulnerabilities) return [];
  
  const vulnerabilities = [];
  Object.entries(auditData.vulnerabilities).forEach(([pkg, vuln]) => {
    const via = Array.isArray(vuln.via) ? vuln.via[0] : vuln.via;
    vulnerabilities.push({
      package: pkg,
      severity: vuln.severity || 'medium',
      title: via?.title || 'Unknown vulnerability',
      description: via?.url || 'No description available',
      fixAvailable: vuln.fixAvailable ? 'Yes' : 'No',
      source: 'npm-audit',
      path: vuln.nodes?.join(' → ') || pkg
    });
  });
  
  return vulnerabilities;
}

// Parse better-npm-audit results for display
function parseBetterNpmAuditForDisplay(betterAuditData) {
  if (!betterAuditData || !betterAuditData.advisories) return [];
  
  const vulnerabilities = [];
  Object.values(betterAuditData.advisories).forEach(advisory => {
    if (advisory.findings) {
      advisory.findings.forEach(finding => {
        const packageName = finding.paths[0]?.split('>')[0] || 'unknown';
        vulnerabilities.push({
          package: packageName,
          severity: advisory.severity || 'medium',
          title: advisory.title || 'Unknown vulnerability',
          description: advisory.url || advisory.overview || 'No description available',
          fixAvailable: 'Manual',
          source: 'better-npm-audit',
          path: finding.paths?.[0] || packageName
        });
      });
    }
  });
  
  return vulnerabilities;
}

// Parse PNPM audit results for display
function parsePnpmAuditForDisplay(pnpmAuditData) {
  if (!pnpmAuditData || !pnpmAuditData.advisories) return [];
  
  const vulnerabilities = [];
  Object.values(pnpmAuditData.advisories).forEach(advisory => {
    if (advisory.findings) {
      advisory.findings.forEach(finding => {
        const packageName = finding.paths[0]?.split('>')[0] || 'unknown';
        vulnerabilities.push({
          package: packageName,
          severity: advisory.severity || 'medium',
          title: advisory.title || 'Unknown vulnerability',
          description: advisory.url || advisory.overview || 'No description available',
          fixAvailable: 'Manual',
          source: 'pnpm-audit',
          path: finding.paths?.[0] || packageName
        });
      });
    }
  });
  
  return vulnerabilities;
}

// Generate vulnerability summary
function generateSummary(vulnerabilities, metrics) {
  if (metrics && metrics.severity) {
    return metrics.severity;
  }
  
  const summary = {
    critical: 0,
    high: 0,
    moderate: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: vulnerabilities.length
  };
  
  vulnerabilities.forEach(vuln => {
    const severity = vuln.severity.toLowerCase();
    if (summary.hasOwnProperty(severity)) {
      summary[severity]++;
    } else {
      summary.medium++;
    }
  });
  
  return summary;
}

// Format Node.js vulnerability report
function formatNodeVulnReport(nodeVulnText) {
  if (!nodeVulnText) {
    return { status: 'unknown', message: 'Node.js vulnerability check not available' };
  }
  
  const lines = nodeVulnText.split('\n').filter(line => line.trim());
  const isVulnerable = nodeVulnText.toLowerCase().includes('vulnerable');
  
  if (isVulnerable) {
    return {
      status: 'vulnerable',
      message: 'Node.js version has known vulnerabilities',
      details: lines
    };
  } else {
    return {
      status: 'safe',
      message: 'Node.js version appears to be safe',
      details: lines
    };
  }
}

// Generate HTML template
function generateHTML(vulnerabilities, summary, metrics, nodeVulnStatus) {
  const timestamp = new Date().toISOString();
  
  // Sort vulnerabilities by severity
  vulnerabilities.sort((a, b) => {
    const aIndex = SEVERITY_ORDER.indexOf(a.severity.toLowerCase());
    const bIndex = SEVERITY_ORDER.indexOf(b.severity.toLowerCase());
    return aIndex - bIndex;
  });
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - ${scanId}</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .node-status {
            padding: 20px 30px;
            border-left: 4px solid;
            margin: 20px 30px;
            border-radius: 4px;
        }
        .node-status.safe {
            background: #d4edda;
            border-color: #28a745;
            color: #155724;
        }
        .node-status.vulnerable {
            background: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        .node-status.unknown {
            background: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .summary-card:hover {
            transform: translateY(-2px);
        }
        .summary-card h3 {
            margin: 0;
            font-size: 2em;
            font-weight: 600;
        }
        .summary-card p {
            margin: 5px 0 0;
            color: #666;
            text-transform: uppercase;
            font-size: 0.8em;
            font-weight: bold;
            letter-spacing: 0.5px;
        }
        .metrics-section {
            padding: 30px;
        }
        .metrics-section h2 {
            color: #333;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .table th,
        .table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        .table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        .table tr:hover {
            background-color: #f8f9fa;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            white-space: nowrap;
        }
        .vulnerability-details {
            padding: 30px;
        }
        .vulnerability-item {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }
        .vulnerability-item:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .vulnerability-header {
            padding: 15px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .vulnerability-body {
            padding: 20px;
        }
        .source-tag {
            background: #6c757d;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            margin-left: 10px;
        }
        .package-path {
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .footer {
            background: #343a40;
            color: white;
            padding: 20px 30px;
            text-align: center;
            font-size: 0.9em;
        }
        .pass { color: #28a745; font-weight: bold; }
        .fail { color: #dc3545; font-weight: bold; }
        .warn { color: #fd7e14; font-weight: bold; }
        .recommendations {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .recommendation-item {
            padding: 10px 0;
            border-bottom: 1px solid #e9ecef;
        }
        .recommendation-item:last-child {
            border-bottom: none;
        }
        .priority-critical { color: #dc3545; font-weight: bold; }
        .priority-high { color: #fd7e14; font-weight: bold; }
        .priority-medium { color: #ffc107; font-weight: bold; }
        .priority-low { color: #28a745; font-weight: bold; }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        .empty-state h3 {
            color: #28a745;
            font-size: 1.5em;
            margin-bottom: 10px;
        }
        @media (max-width: 768px) {
            .summary {
                grid-template-columns: repeat(2, 1fr);
            }
            .vulnerability-header {
                flex-direction: column;
                align-items: flex-start;
            }
            .table {
                font-size: 0.9em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Scan ID: ${scanId} | Generated: ${new Date(timestamp).toLocaleString()}</p>
        </div>
        
        <div class="node-status ${nodeVulnStatus.status}">
            <strong>Node.js Security Status:</strong> ${nodeVulnStatus.message}
            ${nodeVulnStatus.details && nodeVulnStatus.details.length > 0 ? `
            <details style="margin-top: 10px;">
                <summary>View Details</summary>
                <pre style="margin: 10px 0; font-size: 0.9em;">${nodeVulnStatus.details.slice(0, 10).join('\n')}</pre>
            </details>
            ` : ''}
        </div>
        
        <div class="summary">
            ${SEVERITY_ORDER.map(severity => {
              const count = summary[severity] || 0;
              return `
                <div class="summary-card" style="border-left-color: ${SEVERITY_COLORS[severity]}">
                    <h3 style="color: ${SEVERITY_COLORS[severity]}">${count}</h3>
                    <p>${severity}</p>
                </div>
              `;
            }).join('')}
        </div>
        
        <div class="metrics-section">
            <h2>📊 Security Targets</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Current</th>
                        <th>Target</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Critical Vulnerabilities</td>
                        <td>${summary.critical || 0}</td>
                        <td>0</td>
                        <td class="${(summary.critical || 0) === 0 ? 'pass' : 'fail'}">${(summary.critical || 0) === 0 ? 'PASS' : 'FAIL'}</td>
                    </tr>
                    <tr>
                        <td>High Vulnerabilities</td>
                        <td>${summary.high || 0}</td>
                        <td>&lt; 5</td>
                        <td class="${(summary.high || 0) < 5 ? 'pass' : 'fail'}">${(summary.high || 0) < 5 ? 'PASS' : 'FAIL'}</td>
                    </tr>
                    <tr>
                        <td>Medium/Moderate Vulnerabilities</td>
                        <td>${(summary.moderate || 0) + (summary.medium || 0)}</td>
                        <td>&lt; 20</td>
                        <td class="${((summary.moderate || 0) + (summary.medium || 0)) < 20 ? 'pass' : 'fail'}">${((summary.moderate || 0) + (summary.medium || 0)) < 20 ? 'PASS' : 'FAIL'}</td>
                    </tr>
                    <tr>
                        <td>Node.js Security</td>
                        <td>${nodeVulnStatus.status === 'safe' ? 'Safe' : (nodeVulnStatus.status === 'vulnerable' ? 'Vulnerable' : 'Unknown')}</td>
                        <td>Safe</td>
                        <td class="${nodeVulnStatus.status === 'safe' ? 'pass' : (nodeVulnStatus.status === 'vulnerable' ? 'fail' : 'warn')}">${nodeVulnStatus.status === 'safe' ? 'PASS' : (nodeVulnStatus.status === 'vulnerable' ? 'FAIL' : 'WARN')}</td>
                    </tr>
                </tbody>
            </table>
            
            ${metrics && metrics.recommendations && metrics.recommendations.length > 0 ? `
            <div class="recommendations">
                <h3>📋 Recommendations</h3>
                ${metrics.recommendations.map(rec => `
                    <div class="recommendation-item">
                        <span class="priority-${rec.priority.toLowerCase()}">[${rec.priority}]</span>
                        ${rec.action} <small>(${rec.type})</small>
                    </div>
                `).join('')}
            </div>
            ` : ''}
        </div>
        
        <div class="vulnerability-details">
            <h2>🔍 Vulnerability Details</h2>
            ${vulnerabilities.length === 0 ? `
                <div class="empty-state">
                    <h3>🎉 No vulnerabilities found!</h3>
                    <p>Your project appears to be free of known security vulnerabilities.</p>
                    <p><small>Continue monitoring and keep dependencies up to date.</small></p>
                </div>
            ` : ''}
            ${vulnerabilities.slice(0, 50).map(vuln => `
                <div class="vulnerability-item">
                    <div class="vulnerability-header">
                        <div>
                            <strong>${vuln.package}</strong>
                            <span class="source-tag">${vuln.source}</span>
                            ${vuln.path !== vuln.package ? `<div class="package-path">${vuln.path}</div>` : ''}
                        </div>
                        <span class="severity-badge" style="background-color: ${SEVERITY_COLORS[vuln.severity.toLowerCase()]}">${vuln.severity}</span>
                    </div>
                    <div class="vulnerability-body">
                        <h4>${vuln.title}</h4>
                        <p><strong>Description:</strong> ${vuln.description.length > 200 ? vuln.description.substring(0, 200) + '...' : vuln.description}</p>
                        <p><strong>Fix Available:</strong> ${vuln.fixAvailable}</p>
                    </div>
                </div>
            `).join('')}
            
            ${vulnerabilities.length > 50 ? `
                <div style="text-align: center; padding: 20px; color: #6c757d;">
                    <p>Showing first 50 vulnerabilities. Total found: ${vulnerabilities.length}</p>
                    <p>Check the JSON reports for complete details.</p>
                </div>
            ` : ''}
        </div>
        
        <div class="footer">
            <p>Generated by Security Scanner | Focus: Node.js, npm audit, better-npm-audit</p>
            <p><small>Report includes results from: is-my-node-vulnerable, npm audit, better-npm-audit${metrics?.scanCoverage?.scansRun?.includes('pnpm-audit') ? ', pnpm audit' : ''}</small></p>
        </div>
    </div>
</body>
</html>
`;
}

// Main execution
function main() {
  console.log(`Generating HTML report for scan: ${scanId}`);
  
  // Load all reports
  const nodeVulnText = loadTextReport('node-vulnerabilities.txt');
  const npmAudit = loadJsonReport('npm-audit.json');
  const betterNpmAudit = loadJsonReport('better-npm-audit.json');
  const pnpmAudit = loadJsonReport('pnpm-audit.json');
  const metrics = loadJsonReport('metrics.json');
  
  // Parse vulnerabilities from all sources
  let allVulnerabilities = [];
  
  if (npmAudit) {
    allVulnerabilities = allVulnerabilities.concat(parseNpmAuditForDisplay(npmAudit));
  }
  
  if (betterNpmAudit) {
    allVulnerabilities = allVulnerabilities.concat(parseBetterNpmAuditForDisplay(betterNpmAudit));
  }
  
  if (pnpmAudit) {
    allVulnerabilities = allVulnerabilities.concat(parsePnpmAuditForDisplay(pnpmAudit));
  }
  
  // Format Node.js vulnerability status
  const nodeVulnStatus = formatNodeVulnReport(nodeVulnText);
  
  // Generate summary (prefer metrics if available)
  const summary = generateSummary(allVulnerabilities, metrics);
  
  // Generate HTML report
  const html = generateHTML(allVulnerabilities, summary, metrics, nodeVulnStatus);
  
  // Ensure output directory exists
  const outputDir = path.dirname(outputFile);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  // Write HTML file
  fs.writeFileSync(outputFile, html, 'utf8');
  
  console.log(`HTML report generated: ${outputFile}`);
  console.log(`Total vulnerabilities found: ${allVulnerabilities.length}`);
  console.log(`Node.js status: ${nodeVulnStatus.status}`);
  console.log('Summary:', summary);
}

if (require.main === module) {
  main();
}