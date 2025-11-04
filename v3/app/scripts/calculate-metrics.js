#!/usr/bin/env node

// calculate-metrics.js - Calculate security metrics from scan results
const fs = require('fs');
const path = require('path');
const { program } = require('commander');

program
  .option('--scan-id <id>', 'Scan ID')
  .option('--input-dir <dir>', 'Input directory with JSON reports')
  .option('--output-file <file>', 'Output JSON file path')
  .parse();

const { scanId, inputDir, outputFile } = program.opts();

// Load JSON report files
function loadJsonReport(filename) {
  const filePath = path.join(inputDir, 'json', filename);
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(content);
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

// Parse Node.js vulnerability report
function parseNodeVulnerabilities(nodeVulnText) {
  if (!nodeVulnText) return { vulnerable: false, version: 'unknown', issues: [] };
  
  const lines = nodeVulnText.split('\n');
  let vulnerable = false;
  let version = 'unknown';
  let issues = [];
  
  for (const line of lines) {
    if (line.includes('Node.js version')) {
      const versionMatch = line.match(/v(\d+\.\d+\.\d+)/);
      if (versionMatch) {
        version = versionMatch[1];
      }
    }
    
    if (line.toLowerCase().includes('vulnerable') || line.toLowerCase().includes('security')) {
      vulnerable = true;
      issues.push(line.trim());
    }
    
    if (line.toLowerCase().includes('not vulnerable')) {
      vulnerable = false;
    }
  }
  
  return { vulnerable, version, issues };
}

// Parse npm audit results
function parseNpmAudit(auditData) {
  if (!auditData) return { vulnerabilities: [], packages: [], total: 0, severity: {} };
  
  const vulnerabilities = [];
  const packages = new Set();
  let severity = {
    critical: 0,
    high: 0,
    moderate: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  // Handle new npm audit format (npm 7+)
  if (auditData.metadata && auditData.metadata.vulnerabilities) {
    severity = {
      critical: auditData.metadata.vulnerabilities.critical || 0,
      high: auditData.metadata.vulnerabilities.high || 0,
      moderate: auditData.metadata.vulnerabilities.moderate || 0,
      medium: auditData.metadata.vulnerabilities.moderate || 0, // moderate maps to medium
      low: auditData.metadata.vulnerabilities.low || 0,
      info: auditData.metadata.vulnerabilities.info || 0
    };
  }
  
  if (auditData.vulnerabilities) {
    Object.entries(auditData.vulnerabilities).forEach(([pkg, vuln]) => {
      vulnerabilities.push({
        package: pkg,
        severity: vuln.severity || 'medium',
        title: vuln.via?.[0]?.title || 'Unknown vulnerability',
        fixAvailable: vuln.fixAvailable ? 'yes' : 'no',
        source: 'npm-audit'
      });
      packages.add(pkg);
    });
  }
  
  return {
    vulnerabilities,
    packages: Array.from(packages),
    total: vulnerabilities.length,
    severity
  };
}

// Parse better-npm-audit results
function parseBetterNpmAudit(betterAuditData) {
  if (!betterAuditData) return { vulnerabilities: [], packages: [], total: 0 };
  
  const vulnerabilities = [];
  const packages = new Set();
  
  if (betterAuditData.advisories) {
    Object.values(betterAuditData.advisories).forEach(advisory => {
      if (advisory.findings) {
        advisory.findings.forEach(finding => {
          const packageName = finding.paths[0]?.split('>')[0] || 'unknown';
          vulnerabilities.push({
            package: packageName,
            severity: advisory.severity || 'medium',
            title: advisory.title || 'Unknown vulnerability',
            fixAvailable: 'manual',
            source: 'better-npm-audit'
          });
          packages.add(packageName);
        });
      }
    });
  }
  
  return {
    vulnerabilities,
    packages: Array.from(packages),
    total: vulnerabilities.length
  };
}

// Parse PNPM audit results
function parsePnpmAudit(pnpmAuditData) {
  if (!pnpmAuditData) return { vulnerabilities: [], packages: [], total: 0 };
  
  const vulnerabilities = [];
  const packages = new Set();
  
  if (pnpmAuditData.advisories) {
    Object.values(pnpmAuditData.advisories).forEach(advisory => {
      if (advisory.findings) {
        advisory.findings.forEach(finding => {
          const packageName = finding.paths[0]?.split('>')[0] || 'unknown';
          vulnerabilities.push({
            package: packageName,
            severity: advisory.severity || 'medium',
            title: advisory.title || 'Unknown vulnerability',
            fixAvailable: 'manual',
            source: 'pnpm-audit'
          });
          packages.add(packageName);
        });
      }
    });
  }
  
  return {
    vulnerabilities,
    packages: Array.from(packages),
    total: vulnerabilities.length
  };
}

// Consolidate all vulnerabilities
function consolidateVulnerabilities(npmResults, betterNpmResults, pnpmResults) {
  const allVulnerabilities = [
    ...npmResults.vulnerabilities,
    ...betterNpmResults.vulnerabilities,
    ...pnpmResults.vulnerabilities
  ];
  
  const allPackages = new Set([
    ...npmResults.packages,
    ...betterNpmResults.packages,
    ...pnpmResults.packages
  ]);
  
  // Deduplicate vulnerabilities by package + severity + source
  const uniqueVulns = [];
  const seen = new Set();
  
  allVulnerabilities.forEach(vuln => {
    const key = `${vuln.package}-${vuln.severity}-${vuln.source}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueVulns.push(vuln);
    }
  });
  
  return {
    vulnerabilities: uniqueVulns,
    packages: Array.from(allPackages),
    total: uniqueVulns.length
  };
}

// Calculate severity distribution
function calculateSeverityDistribution(vulnerabilities) {
  const distribution = {
    critical: 0,
    high: 0,
    moderate: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  vulnerabilities.forEach(vuln => {
    const severity = vuln.severity.toLowerCase();
    if (distribution.hasOwnProperty(severity)) {
      distribution[severity]++;
    } else {
      // Map unknown severities
      if (severity === 'moderate') {
        distribution.moderate++;
      } else {
        distribution.medium++;
      }
    }
  });
  
  return distribution;
}

// Calculate fixability metrics
function calculateFixabilityMetrics(vulnerabilities) {
  const fixable = {
    yes: 0,
    manual: 0,
    no: 0
  };
  
  vulnerabilities.forEach(vuln => {
    if (fixable.hasOwnProperty(vuln.fixAvailable)) {
      fixable[vuln.fixAvailable]++;
    } else {
      fixable.manual++;
    }
  });
  
  const total = vulnerabilities.length;
  const automaticFixRate = total > 0 ? Math.round((fixable.yes / total) * 100) : 0;
  
  return {
    fixable,
    automaticFixRate
  };
}

// Calculate risk score
function calculateRiskScore(severity) {
  const weights = {
    critical: 10,
    high: 7,
    moderate: 4,
    medium: 4,
    low: 1,
    info: 0
  };
  
  return (
    severity.critical * weights.critical +
    severity.high * weights.high +
    severity.moderate * weights.moderate +
    severity.medium * weights.medium +
    severity.low * weights.low +
    severity.info * weights.info
  );
}

// Determine overall security posture
function determineSecurityPosture(severity, riskScore, nodeVuln) {
  if (nodeVuln.vulnerable) {
    return {
      level: 'CRITICAL',
      color: 'red',
      message: 'Node.js version has known vulnerabilities - update immediately',
      priority: 1
    };
  } else if (severity.critical > 0) {
    return {
      level: 'CRITICAL',
      color: 'red',
      message: 'Critical vulnerabilities found - immediate action required',
      priority: 1
    };
  } else if (severity.high >= 5) {
    return {
      level: 'HIGH_RISK',
      color: 'orange',
      message: 'High risk - too many high-severity vulnerabilities',
      priority: 2
    };
  } else if (severity.moderate + severity.medium >= 20) {
    return {
      level: 'MEDIUM_RISK',
      color: 'yellow',
      message: 'Medium risk - many medium-severity vulnerabilities',
      priority: 3
    };
  } else if (riskScore > 20) {
    return {
      level: 'LOW_RISK',
      color: 'orange',
      message: 'Low risk - but monitor vulnerability trends',
      priority: 4
    };
  } else {
    return {
      level: 'GOOD',
      color: 'green',
      message: 'Good security posture - maintain current practices',
      priority: 5
    };
  }
}

// Generate recommendations
function generateRecommendations(metrics, nodeVuln) {
  const recommendations = [];
  
  if (nodeVuln.vulnerable) {
    recommendations.push({
      priority: 'CRITICAL',
      action: `Update Node.js from v${nodeVuln.version} to latest LTS version`,
      type: 'runtime'
    });
  }
  
  if (metrics.severity.critical > 0) {
    recommendations.push({
      priority: 'CRITICAL',
      action: `Fix ${metrics.severity.critical} critical vulnerabilities immediately`,
      type: 'security'
    });
  }
  
  if (metrics.severity.high >= 5) {
    recommendations.push({
      priority: 'HIGH',
      action: `Address ${metrics.severity.high} high-severity vulnerabilities`,
      type: 'security'
    });
  }
  
  if (metrics.fixability.automaticFixRate < 60) {
    recommendations.push({
      priority: 'MEDIUM',
      action: 'Run "npm audit fix" to automatically resolve fixable issues',
      type: 'maintenance'
    });
  }
  
  if (metrics.severity.moderate + metrics.severity.medium >= 10) {
    recommendations.push({
      priority: 'LOW',
      action: 'Review and address medium-severity vulnerabilities when possible',
      type: 'maintenance'
    });
  }
  
  if (metrics.packages.length > 100) {
    recommendations.push({
      priority: 'LOW',
      action: 'Consider dependency audit to reduce attack surface',
      type: 'architecture'
    });
  }
  
  return recommendations;
}

// Main execution
function main() {
  console.log(`Calculating metrics for scan: ${scanId}`);
  
  // Load all reports
  const nodeVulnText = loadTextReport('node-vulnerabilities.txt');
  const npmAudit = loadJsonReport('npm-audit.json');
  const betterNpmAudit = loadJsonReport('better-npm-audit.json');
  const pnpmAudit = loadJsonReport('pnpm-audit.json');
  
  // Parse results
  const nodeVuln = parseNodeVulnerabilities(nodeVulnText);
  const npmResults = parseNpmAudit(npmAudit);
  const betterNpmResults = parseBetterNpmAudit(betterNpmAudit);
  const pnpmResults = parsePnpmAudit(pnpmAudit);
  
  // Consolidate vulnerabilities
  const consolidated = consolidateVulnerabilities(npmResults, betterNpmResults, pnpmResults);
  
  // Calculate metrics
  const severity = calculateSeverityDistribution(consolidated.vulnerabilities);
  // Use npm audit severity if available (more accurate)
  const finalSeverity = npmResults.severity.critical > 0 ? npmResults.severity : severity;
  
  const fixability = calculateFixabilityMetrics(consolidated.vulnerabilities);
  const riskScore = calculateRiskScore(finalSeverity);
  const posture = determineSecurityPosture(finalSeverity, riskScore, nodeVuln);
  
  const metrics = {
    scanId,
    timestamp: new Date().toISOString(),
    nodeJs: {
      version: nodeVuln.version,
      vulnerable: nodeVuln.vulnerable,
      issues: nodeVuln.issues
    },
    summary: {
      total: consolidated.total,
      packages: consolidated.packages.length,
      ...finalSeverity
    },
    severity: finalSeverity,
    fixability,
    riskScore,
    posture,
    recommendations: generateRecommendations({ severity: finalSeverity, fixability, packages: consolidated.packages }, nodeVuln),
    scanCoverage: {
      scansRun: [
        nodeVulnText ? 'node-vulnerable' : null,
        npmAudit ? 'npm-audit' : null,
        betterNpmAudit ? 'better-npm-audit' : null,
        pnpmAudit ? 'pnpm-audit' : null
      ].filter(Boolean),
      totalScans: 4,
      coverage: Math.round((Object.values({
        nodeVulnText,
        npmAudit,
        betterNpmAudit,
        pnpmAudit
      }).filter(Boolean).length / 4) * 100)
    },
    targets: {
      critical: { current: finalSeverity.critical, target: 0, status: finalSeverity.critical === 0 ? 'PASS' : 'FAIL' },
      high: { current: finalSeverity.high, target: 5, status: finalSeverity.high < 5 ? 'PASS' : 'FAIL' },
      medium: { current: finalSeverity.moderate + finalSeverity.medium, target: 20, status: (finalSeverity.moderate + finalSeverity.medium) < 20 ? 'PASS' : 'FAIL' },
      nodeVulnerable: { current: nodeVuln.vulnerable, target: false, status: !nodeVuln.vulnerable ? 'PASS' : 'FAIL' },
      automaticFixRate: { current: fixability.automaticFixRate, target: 60, status: fixability.automaticFixRate >= 60 ? 'PASS' : 'WARN' }
    },
    rawData: {
      consolidatedVulnerabilities: consolidated.vulnerabilities.slice(0, 100), // Limit for size
      sources: ['npm-audit', 'better-npm-audit', 'pnpm-audit', 'node-vulnerable']
    }
  };
  
  // Ensure output directory exists
  const outputDir = path.dirname(outputFile);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  // Write metrics file
  fs.writeFileSync(outputFile, JSON.stringify(metrics, null, 2), 'utf8');
  
  console.log(`Metrics calculated and saved to: ${outputFile}`);
  console.log(`Security Posture: ${posture.level} (${posture.message})`);
  console.log(`Risk Score: ${riskScore}`);
  console.log('Severity Distribution:', finalSeverity);
  console.log(`Node.js Status: v${nodeVuln.version} - ${nodeVuln.vulnerable ? 'VULNERABLE' : 'OK'}`);
}

if (require.main === module) {
  main();
}