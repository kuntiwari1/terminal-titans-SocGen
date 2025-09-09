"use client"

import { useState } from "react"
import GlassmorphicContainer from "../components/layout/GlassmorphicContainer"
import ScanOutputDisplay from "../components/dashboard/ScanOutputDisplay"
import LLMInsightsDisplay from "../components/dashboard/LLMInsightsDisplay"
import FileUpload from "../components/FileUpload"
import { Button } from "../components/ui/button" // Corrected import path
import { Input } from "../components/ui/input" // Corrected import path
import { toast } from "react-hot-toast"

export default function Dashboard() {
  const [scanOutput, setScanOutput] = useState("")
  const [llmInsights, setLlmInsights] = useState([])
  const [customTool, setCustomTool] = useState("")
  const [loading, setLoading] = useState(false)
  const [currentScanId, setCurrentScanId] = useState(null)

  const handleScanStart = () => {
    setScanOutput("Scanning in progress... Please wait.")
    setLlmInsights("Generating insights...")
  }

  const handleScanComplete = (output, insights) => {
    setScanOutput(output)
    setLlmInsights(insights)
  }

  const handleScan = async (scanType) => {
    setLoading(true)
    handleScanStart()

    try {
      const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/scan/nmap`, {
        // Added /api prefix
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ scanType }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      handleScanComplete(data.rawOutput, data.vulnerabilities)
      setCurrentScanId(data.scanId)
      toast.success(`Nmap scan (${scanType}) simulated and analyzed!`)
    } catch (error) {
      console.error("Error running Nmap scan:", error)
      toast.error(`Failed to run scan: ${error.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleCustomToolScan = async () => {
    if (!customTool.trim()) {
      toast.error("Please enter a custom tool command.")
      return
    }

    setLoading(true)
    handleScanStart()

    try {
      const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/scan/custom`, {
        // Added /api prefix
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ tool: customTool }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      handleScanComplete(data.rawOutput, data.vulnerabilities)
      setCurrentScanId(data.scanId)
      toast.success(`${customTool} scan simulated and analyzed!`)
    } catch (error) {
      console.error("Error running custom tool scan:", error)
      toast.error(`Failed to run custom tool: ${error.message}`)
    } finally {
      setLoading(false)
      setCustomTool("")
    }
  }

  const handleFileProcessed = (data) => {
    handleScanComplete(data.rawOutput, data.vulnerabilities)
    setCurrentScanId(data.scanId)
  }

  const handleDownloadReport = async () => {
    if (!currentScanId) {
      toast.error("No scan data available to generate a report.")
      return
    }

    try {
      const response = await fetch(`${import.meta.env.VITE_BACKEND_URL}/api/report/${currentScanId}`) // Added /api prefix
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `pentest_report_${currentScanId}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
      toast.success("PDF report downloaded successfully!")
    } catch (error) {
      console.error("Error downloading report:", error)
      toast.error(`Failed to download report: ${error.message}`)
    }
  }

  return (
    <GlassmorphicContainer className="w-full">
      <h2 className="text-2xl font-bold mb-6 text-white">Run New Scan</h2>

      <div className="flex flex-col lg:flex-row gap-6">
        <div className="lg:w-1/3">
          <FileUpload onScanStart={handleScanStart} onScanComplete={handleScanComplete} />
        </div>
        <div className="lg:w-2/3 flex flex-col gap-6">
          <ScanOutputDisplay output={scanOutput} />
          <LLMInsightsDisplay insights={llmInsights} />
        </div>
      </div>

      {/* Nmap Scan Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="flex flex-col gap-3">
          <h3 className="text-xl font-semibold text-white">Nmap Scans (Simulated)</h3>
          <Button
            onClick={() => handleScan("nmap -sV -A -O")}
            disabled={loading}
            className="bg-purple-600 hover:bg-purple-700 text-white"
          >
            {loading ? "Scanning..." : "Run Nmap -sV -A -O"}
          </Button>
          <Button
            onClick={() => handleScan("nmap --script vuln")}
            disabled={loading}
            className="bg-purple-600 hover:bg-purple-700 text-white"
          >
            {loading ? "Scanning..." : "Run Nmap --script vuln"}
          </Button>
        </div>

        {/* Add More Advanced Recon Tools */}
        <div className="flex flex-col gap-3">
          <h3 className="text-xl font-semibold text-white">Add Custom Recon Tool (Simulated)</h3>
          <Input
            type="text"
            placeholder="e.g., Nikto, WhatWeb, Nuclei"
            value={customTool}
            onChange={(e) => setCustomTool(e.target.value)}
            className="bg-gray-700 text-white border-gray-600 placeholder-gray-400"
            disabled={loading}
          />
          <Button
            onClick={handleCustomToolScan}
            disabled={loading || !customTool.trim()}
            className="bg-teal-600 hover:bg-teal-700 text-white"
          >
            {loading ? "Running..." : `Run ${customTool || "Custom Tool"}`}
          </Button>
        </div>
      </div>
    </GlassmorphicContainer>
  )
}
