import { Router } from "express"
import multer from "multer"
import { exec } from "child_process"
import { promisify } from "util"
import rateLimit from 'express-rate-limit'
import validator from 'validator'
import xss from 'xss'
import dns from 'dns'
import { promisify as utilPromisify } from 'util'
import { generateGeminiInsights } from "../utils/gemini-analyzer.js"
import { saveScanResult, getScanHistory, getScanById } from "../utils/db-queries.js"

const router = Router()
const upload = multer({ storage: multer.memoryStorage() })
const execPromise = promisify(exec)
const dnsResolve = utilPromisify(dns.resolve)

// Current user and timestamp
const CURRENT_USER = 'Prateek-glitch'
const CURRENT_TIMESTAMP = '2025-07-12 14:53:44'

// Rate limiting middleware
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many scan requests, please try again later.'
})

// Resolve domain to IP
async function resolveTarget(target) {
  try {
    const url = new URL(target)
    const ips = await dnsResolve(url.hostname)
    return ips[0]
  } catch (error) {
    throw new Error(`Failed to resolve target domain: ${error.message}`)
  }
}

// Extract domain from URL
function extractDomain(target) {
  try {
    const url = new URL(target)
    return url.hostname
  } catch (error) {
    throw new Error(`Failed to extract domain from URL: ${error.message}`)
  }
}

// Validate target URL
function validateTarget(target) {
  try {
    if (!target || typeof target !== 'string') {
      throw new Error('Target URL is required')
    }

    target = target.trim()

    if (!validator.isURL(target, {
      protocols: ['http', 'https'],
      require_protocol: true,
      require_valid_protocol: true
    })) {
      throw new Error('Invalid URL format. URL must start with http:// or https://')
    }

    const url = new URL(target)

    if (
      url.hostname === 'localhost' ||
      url.hostname === '127.0.0.1' ||
      /^192\.168\./.test(url.hostname) ||
      /^10\./.test(url.hostname) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(url.hostname)
    ) {
      throw new Error('Scanning local or private networks is not allowed')
    }

    return true
  } catch (error) {
    throw new Error(error.message)
  }
}

// Execute command with sudo
async function execWithSudo(command) {
  try {
    const sudoCommand = `sudo -n ${command}`
    const { stdout, stderr } = await execPromise(sudoCommand, {
      timeout: 600000,
      maxBuffer: 1024 * 1024 * 10
    })
    
    if (stderr) {
      console.error(`[${CURRENT_TIMESTAMP}] Command stderr:`, stderr)
    }
    
    return stdout || stderr
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Command execution error:`, error)
    if (error.message.includes('sudo: a password is required')) {
      throw new Error('Sudo access not properly configured')
    }
    throw error
  }
}

// Execute command without sudo
async function execWithoutSudo(command) {
  try {
    const { stdout, stderr } = await execPromise(command, {
      timeout: 600000,
      maxBuffer: 1024 * 1024 * 10
    })
    
    if (stderr) {
      console.error(`[${CURRENT_TIMESTAMP}] Command stderr:`, stderr)
    }
    
    return stdout || stderr
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Command execution error:`, error)
    throw error
  }
}

// Run Nmap scan
async function runNmapScan(scanType, targetUrl) {
  try {
    const targetIP = await resolveTarget(targetUrl)
    console.log(`[${CURRENT_TIMESTAMP}] Resolved ${targetUrl} to ${targetIP}`)

    let cmd = ''
    switch(scanType) {
      case 'nmap-sV-A-O':
        cmd = `nmap -Pn -sV -A -O ${targetIP} -T4 --privileged`
        break
      case 'nmap-script-vuln':
        cmd = `nmap -Pn -sV --script vuln ${targetIP} -T4 --privileged`
        break
      default:
        throw new Error('Invalid scan type')
    }
    
    console.log(`[${CURRENT_TIMESTAMP}] Executing Nmap command: ${cmd}`)
    const output = await execWithSudo(cmd)
    
    if (!output || output.includes('0 hosts up')) {
      throw new Error('No hosts were found up during the scan. The target might be blocking our probes.')
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Nmap scan error:`, error)
    throw new Error(`Nmap scan failed: ${error.message}`)
  }
}

// Run Nikto scan
async function runNiktoScan(targetUrl) {
  try {
    const cmd = `nikto -h ${targetUrl} -Format txt -nointeractive -Tuning 123bde`
    const output = await execWithSudo(cmd)
    
    if (!output) {
      throw new Error('Nikto scan produced no output')
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Nikto scan error:`, error)
    throw new Error(`Nikto scan failed: ${error.message}`)
  }
}

// Run WhatWeb scan
async function runWhatWebScan(targetUrl) {
  try {
    const cmd = `whatweb -a 3 --no-errors ${targetUrl}`
    const output = await execWithSudo(cmd)
    
    if (!output) {
      throw new Error('WhatWeb scan produced no output')
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] WhatWeb scan error:`, error)
    throw new Error(`WhatWeb scan failed: ${error.message}`)
  }
}

// Run Nuclei scan
async function runNucleiScan(targetUrl) {
  try {
    const cmd = `nuclei -u ${targetUrl} -severity low,medium,high,critical -silent -timeout 5`
    const output = await execWithSudo(cmd)
    
    if (!output) {
      return "No vulnerabilities found by Nuclei"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Nuclei scan error:`, error)
    throw new Error(`Nuclei scan failed: ${error.message}`)
  }
}

// Run Amass scan
async function runAmassScan(targetUrl) {
  try {
    const domain = extractDomain(targetUrl)
    const cmd = `amass enum -passive -d ${domain} -timeout 10`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No subdomains found by Amass"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Amass scan error:`, error)
    throw new Error(`Amass scan failed: ${error.message}`)
  }
}

// Run httpx scan
async function runHttpxScan(targetUrl) {
  try {
    const domain = extractDomain(targetUrl)
    const cmd = `echo ${domain} | httpx -title -tech-detect -status-code -content-length -timeout 10`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No HTTP information found by httpx"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] httpx scan error:`, error)
    throw new Error(`httpx scan failed: ${error.message}`)
  }
}

// Run Subfinder scan
async function runSubfinderScan(targetUrl) {
  try {
    const domain = extractDomain(targetUrl)
    const cmd = `subfinder -d ${domain} -silent -timeout 10`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No subdomains found by Subfinder"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Subfinder scan error:`, error)
    throw new Error(`Subfinder scan failed: ${error.message}`)
  }
}

// Run dnsx scan
async function runDnsxScan(targetUrl) {
  try {
    const domain = extractDomain(targetUrl)
    const cmd = `echo ${domain} | dnsx -resp -a -aaaa -cname -mx -ns -txt -silent`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No DNS information found by dnsx"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] dnsx scan error:`, error)
    throw new Error(`dnsx scan failed: ${error.message}`)
  }
}

// Run naabu scan
async function runNaabuScan(targetUrl) {
  try {
    const domain = extractDomain(targetUrl)
    const cmd = `naabu -host ${domain} -top-ports 1000 -silent -timeout 10000`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No open ports found by naabu"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] naabu scan error:`, error)
    throw new Error(`naabu scan failed: ${error.message}`)
  }
}

// Run Wappalyzer scan
async function runWappalyzerScan(targetUrl) {
  try {
    const cmd = `wappalyzer ${targetUrl}`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No technology stack detected by Wappalyzer"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Wappalyzer scan error:`, error)
    throw new Error(`Wappalyzer scan failed: ${error.message}`)
  }
}

// Run testssl.sh scan
async function runTestsslScan(targetUrl) {
  try {
    const domain = extractDomain(targetUrl)
    const cmd = `testssl.sh --fast --parallel ${domain}:443`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No SSL/TLS information found by testssl.sh"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] testssl.sh scan error:`, error)
    throw new Error(`testssl.sh scan failed: ${error.message}`)
  }
}

// Run Feroxbuster scan
async function runFeroxbusterScan(targetUrl) {
  try {
    const cmd = `feroxbuster -u ${targetUrl} -t 10 -d 2 -w /usr/share/wordlists/dirb/common.txt --silent`
    const output = await execWithoutSudo(cmd)
    
    if (!output) {
      return "No directories found by Feroxbuster"
    }
    
    return xss(output)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Feroxbuster scan error:`, error)
    throw new Error(`Feroxbuster scan failed: ${error.message}`)
  }
}

// Route to run multiple scans
router.post("/run-scans", scanLimiter, async (req, res) => {
  const { targetUrl, selectedTools } = req.body

  try {
    if (!targetUrl || !selectedTools || !Array.isArray(selectedTools) || selectedTools.length === 0) {
      throw new Error('Target URL and at least one tool are required')
    }

    validateTarget(targetUrl)

    let combinedRawOutput = ""
    let combinedVulnerabilities = []
    let combinedSummary = ""
    let combinedKeyPoints = []
    let errors = []

    for (const tool of selectedTools) {
      try {
        let toolOutput = ""
        let toolInsights = { vulnerabilities: [], summary: "", keyPoints: [] }

        console.log(`[${CURRENT_TIMESTAMP}] Starting ${tool} scan for ${targetUrl} by ${CURRENT_USER}`)

        switch (tool) {
          case "nmap-sV-A-O":
            toolOutput = await runNmapScan("nmap-sV-A-O", targetUrl)
            break
          case "nmap-script-vuln":
            toolOutput = await runNmapScan("nmap-script-vuln", targetUrl)
            break
          case "nikto":
            toolOutput = await runNiktoScan(targetUrl)
            break
          case "whatweb":
            toolOutput = await runWhatWebScan(targetUrl)
            break
          case "nuclei":
            toolOutput = await runNucleiScan(targetUrl)
            break
          case "amass":
            toolOutput = await runAmassScan(targetUrl)
            break
          case "httpx":
            toolOutput = await runHttpxScan(targetUrl)
            break
          case "subfinder":
            toolOutput = await runSubfinderScan(targetUrl)
            break
          case "dnsx":
            toolOutput = await runDnsxScan(targetUrl)
            break
          case "naabu":
            toolOutput = await runNaabuScan(targetUrl)
            break
          case "wappalyzer":
            toolOutput = await runWappalyzerScan(targetUrl)
            break
          case "testssl":
            toolOutput = await runTestsslScan(targetUrl)
            break
          case "feroxbuster":
            toolOutput = await runFeroxbusterScan(targetUrl)
            break
          default:
            throw new Error(`Unknown tool selected: ${tool}`)
        }

        console.log(`[${CURRENT_TIMESTAMP}] Completed ${tool} scan for ${targetUrl}`)

        toolInsights = await generateGeminiInsights(toolOutput)

        combinedRawOutput += `\n--- Output from ${tool} for ${targetUrl} at ${CURRENT_TIMESTAMP} ---\n${toolOutput}\n`
        combinedVulnerabilities = combinedVulnerabilities.concat(toolInsights.vulnerabilities)
        combinedSummary += `${toolInsights.summary}\n`
        combinedKeyPoints = combinedKeyPoints.concat(toolInsights.keyPoints)
      } catch (error) {
        console.error(`[${CURRENT_TIMESTAMP}] Error in ${tool} scan:`, error)
        errors.push(`${tool}: ${error.message}`)
        combinedRawOutput += `\n--- Error from ${tool} for ${targetUrl} at ${CURRENT_TIMESTAMP} ---\n${error.message}\n`
      }
    }

    if (errors.length === selectedTools.length) {
      throw new Error(`All scans failed: ${errors.join('; ')}`)
    }

    const savedScan = await saveScanResult(
      targetUrl,
      combinedRawOutput,
      JSON.stringify({
        vulnerabilities: combinedVulnerabilities,
        summary: combinedSummary.trim(),
        keyPoints: combinedKeyPoints,
        timestamp: CURRENT_TIMESTAMP,
        user: CURRENT_USER,
        errors: errors.length > 0 ? errors : undefined
      })
    )

    const response = {
      message: errors.length > 0 
        ? `Scans completed with some errors for ${targetUrl}` 
        : `Scans completed successfully for ${targetUrl}!`,
      rawOutput: combinedRawOutput,
      vulnerabilities: combinedVulnerabilities,
      summary: combinedSummary.trim(),
      keyPoints: combinedKeyPoints,
      scanId: savedScan.id,
      timestamp: CURRENT_TIMESTAMP,
      errors: errors.length > 0 ? errors : undefined
    }

    res.json(response)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error running scans:`, error)
    res.status(400).json({ error: error.message })
  }
})

// Route to handle file uploads
router.post("/upload", upload.single("scanFile"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded." })
  }

  try {
    const rawOutput = req.file.buffer.toString("utf8")
    const targetUrl = "File Upload"

    const llmResult = await generateGeminiInsights(rawOutput)
    const savedScan = await saveScanResult(
      targetUrl,
      rawOutput,
      JSON.stringify({
        ...llmResult,
        timestamp: CURRENT_TIMESTAMP,
        user: CURRENT_USER
      })
    )

    res.json({
      message: "File processed successfully!",
      rawOutput: rawOutput,
      ...llmResult,
      scanId: savedScan.id,
      timestamp: CURRENT_TIMESTAMP
    })
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error processing file:`, error)
    res.status(500).json({ error: "Failed to process file", details: error.message })
  }
})

// Route to get scan history
router.get("/history", async (req, res) => {
  try {
    const history = await getScanHistory()
    const parsedHistory = history.map((scan) => ({
      ...scan,
      llm_insights: JSON.parse(scan.llm_insights)
    }))
    res.json(parsedHistory)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error fetching history:`, error)
    res.status(500).json({ error: "Failed to retrieve history" })
  }
})

// Route to get dashboard summary
router.get("/dashboard-summary", async (req, res) => {
  try {
    const history = await getScanHistory()
    const recentScans = history.slice(0, 5)

    const summary = {
      statistics: {
        totalScans: history.length,
        vulnerabilitiesByRisk: countVulnerabilitiesByRisk(history),
        recentActivity: getRecentActivity(history),
        scansByStatus: getScansByStatus(history)
      },
      recentScans: recentScans.map(scan => ({
        id: scan.id,
        targetUrl: scan.target_url,
        timestamp: scan.timestamp,
        vulnerabilities: JSON.parse(scan.llm_insights).vulnerabilities.length,
        status: scan.status,
        criticalCount: countCriticalVulnerabilities(scan)
      })),
      user: CURRENT_USER,
      lastUpdated: CURRENT_TIMESTAMP
    }

    res.json(summary)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error fetching dashboard summary:`, error)
    res.status(500).json({ error: "Failed to retrieve dashboard summary" })
  }
})

// Route to get patch recommendations
router.get("/patch-recommendations/:scanId", async (req, res) => {
  try {
    const scan = await getScanById(req.params.scanId)
    if (!scan) {
      return res.status(404).json({ error: "Scan not found." })
    }

    const insights = JSON.parse(scan.llm_insights)
    
    const patchRecommendations = await generateGeminiInsights(
      JSON.stringify({
        type: "patch_recommendations",
        vulnerabilities: insights.vulnerabilities,
        scanOutput: scan.scan_output
      })
    )

    const response = {
      scanId: scan.id,
      targetUrl: scan.target_url,
      timestamp: CURRENT_TIMESTAMP,
      recommendations: patchRecommendations.patches || [],
      suggestedActions: generatePatchSuggestions(patchRecommendations),
      priorityLevel: calculatePriorityLevel(insights.vulnerabilities),
      estimatedEffort: calculateEffort(patchRecommendations)
    }

    res.json(response)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error generating patch recommendations:`, error)
    res.status(500).json({ error: "Failed to generate patch recommendations" })
  }
})

// Helper functions
function countVulnerabilitiesByRisk(history) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0
  }

  history.forEach(scan => {
    const insights = JSON.parse(scan.llm_insights)
    insights.vulnerabilities.forEach(vuln => {
      const severity = vuln.severity || 'Info'
      counts[severity]++
    })
  })

  return counts
}

function getRecentActivity(history) {
  return history
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 10)
    .map(scan => ({
      id: scan.id,
      type: 'scan',
      targetUrl: scan.target_url,
      timestamp: scan.timestamp,
      user: scan.user || CURRENT_USER,
      status: scan.status,
      vulnerabilityCount: JSON.parse(scan.llm_insights).vulnerabilities.length
    }))
}

function getScansByStatus(history) {
  return {
    completed: history.filter(scan => scan.status === 'completed').length,
    inProgress: history.filter(scan => scan.status === 'in_progress').length,
    failed: history.filter(scan => scan.status === 'failed').length
  }
}

function countCriticalVulnerabilities(scan) {
  const insights = JSON.parse(scan.llm_insights)
  return insights.vulnerabilities.filter(v => 
    v.severity === 'Critical' || v.severity === 'High'
  ).length
}

function generatePatchSuggestions(recommendations) {
  return recommendations.patches?.map(patch => ({
    vulnerability: patch.vulnerability,
    priority: patch.severity,
    suggestedFix: patch.remediation,
    estimatedEffort: calculatePatchEffort(patch),
    dependencies: patch.dependencies || [],
    impact: patch.impact || 'Unknown',
    testingRequired: patch.testing_required || true
  })) || []
}

function calculatePriorityLevel(vulnerabilities) {
  const severityScores = {
    Critical: 5,
    High: 4,
    Medium: 3,
    Low: 2,
    Info: 1
  }

  const totalScore = vulnerabilities.reduce((score, vuln) => 
    score + (severityScores[vuln.severity] || 1), 0)
  
  const averageScore = totalScore / vulnerabilities.length

  if (averageScore >= 4) return 'Immediate'
  if (averageScore >= 3) return 'High Priority'
  if (averageScore >= 2) return 'Medium Priority'
  return 'Low Priority'
}

function calculatePatchEffort(patch) {
  const complexityScores = {
    High: 5,
    Medium: 3,
    Low: 1
  }

  const factors = {
    complexity: complexityScores[patch.complexity] || 3,
    dependencies: (patch.dependencies?.length || 0) * 0.5,
    testing: patch.testing_required ? 2 : 0,
    impact: patch.critical_system ? 3 : 1
  }

  const totalScore = Object.values(factors).reduce((sum, score) => sum + score, 0)

  if (totalScore >= 10) return 'Major Effort'
  if (totalScore >= 6) return 'Moderate Effort'
  return 'Minor Effort'
}

function calculateEffort(recommendations) {
  const patches = recommendations.patches || []
  const totalEffort = patches.reduce((total, patch) => {
    const effort = calculatePatchEffort(patch)
    return total + (effort === 'Major Effort' ? 3 : effort === 'Moderate Effort' ? 2 : 1)
  }, 0)

  return {
    totalPatchCount: patches.length,
    estimatedHours: totalEffort * 2,
    recommendedTeamSize: totalEffort > 10 ? 3 : totalEffort > 5 ? 2 : 1,
    complexity: totalEffort > 15 ? 'High' : totalEffort > 8 ? 'Medium' : 'Low'
  }
}

// Route to download report
router.get("/report/:scanId", async (req, res) => {
  const { scanId } = req.params

  try {
    const scan = await getScanById(scanId)
    if (!scan) {
      return res.status(404).json({ error: "Scan not found." })
    }

    const llmInsights = JSON.parse(scan.llm_insights)

    let pdfContent = `
Pentest Report
Generated at: ${CURRENT_TIMESTAMP}
Scan ID: ${scan.id}
Target: ${scan.target_url || "N/A"}
Generated by: ${CURRENT_USER}

================================================================================
1. Executive Summary
================================================================================
${llmInsights.summary || "No summary available."}

================================================================================
2. Key Findings / Highlights
================================================================================
${
  llmInsights.keyPoints && llmInsights.keyPoints.length > 0
    ? llmInsights.keyPoints.map((point) => `- ${point}`).join("\n")
    : "No key points identified."
}

================================================================================
3. Detailed Vulnerabilities
================================================================================
`

    if (llmInsights.vulnerabilities && llmInsights.vulnerabilities.length > 0) {
      llmInsights.vulnerabilities.forEach((v, index) => {
        pdfContent += `
--------------------------------------------------------------------------------
Vulnerability ${index + 1}: ${v.vulnerability}
--------------------------------------------------------------------------------
Risk Level: ${v.riskLevel || "N/A"} (Severity: ${v.severity || "N/A"})
Occurrence: ${v.occurrence || "N/A"}
Cause: ${v.cause || "N/A"}
CVE ID(s): ${v.cve || "N/A"}
References: ${v.references && v.references.length > 0 ? v.references.join(", ") : "N/A"}

Remediation:
${v.remediation || "No remediation steps provided."}

${v.mitigation ? `Mitigation: ${v.mitigation}\n` : ""}
`
      })
    } else {
      pdfContent += "No detailed vulnerabilities identified.\n"
    }

    pdfContent += `
================================================================================
4. Raw Scan Output
================================================================================
${scan.scan_output}

================================================================================
End of Report
Generated at: ${CURRENT_TIMESTAMP}
Generated by: ${CURRENT_USER}
================================================================================
`

    res.setHeader("Content-Type", "application/pdf")
    res.setHeader("Content-Disposition", `attachment; filename=pentest_report_${scanId}_${CURRENT_TIMESTAMP}.pdf`)
    res.send(pdfContent)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error generating report:`, error)
    res.status(500).json({ error: "Failed to generate report" })
  }
})

// Route to fetch scan details
router.get("/scan-details/:scanId", async (req, res) => {
  try {
    const scan = await getScanById(req.params.scanId)
    if (!scan) {
      return res.status(404).json({ error: "Scan not found." })
    }
    const parsedScan = {
      ...scan,
      llm_insights: JSON.parse(scan.llm_insights)
    }
    res.json(parsedScan)
  } catch (error) {
    console.error(`[${CURRENT_TIMESTAMP}] Error fetching scan details:`, error)
    res.status(500).json({ error: "Failed to retrieve scan details" })
  }
})

export default router