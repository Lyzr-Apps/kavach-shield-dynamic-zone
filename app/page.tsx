'use client'

import { useState, useRef, useEffect } from 'react'
import { FaShieldAlt, FaExclamationTriangle, FaCheckCircle, FaPhone, FaUpload, FaSpinner, FaDownload, FaCopy, FaExpand, FaCompress } from 'react-icons/fa'
import { MdSecurity, MdWarning, MdCheckCircle, MdError } from 'react-icons/md'
import { callAIAgent, uploadFiles } from '@/lib/aiAgent'
import { ManagerVerdict, WarRoomLogEntry, ChecklistItem, ResponseAgentOutput } from '@/types/agent'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

const AGENT_IDS = {
  manager: '6985a36976d4fd436bf4b7ce',
  forensic: '6985a31a5eb49186d63e5dd4',
  intelligence: '6985a332e17e33c11eed1b4e',
  response: '6985a34df7f7d3ffa5d86661',
}

export default function Home() {
  const [panicMode, setPanicMode] = useState(false)
  const [uploadedImage, setUploadedImage] = useState<File | null>(null)
  const [pastedText, setPastedText] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [verdict, setVerdict] = useState<ManagerVerdict | null>(null)
  const [warRoomLogs, setWarRoomLogs] = useState<WarRoomLogEntry[]>([])
  const [checklist, setChecklist] = useState<ChecklistItem[]>([])
  const [uploadProgress, setUploadProgress] = useState(0)
  const [panicModeInput, setPanicModeInput] = useState('')
  const [panicThreats, setPanicThreats] = useState<string[]>([])
  const [showReport, setShowReport] = useState(false)
  const [showCopyModal, setShowCopyModal] = useState(false)
  const [copyModalText, setCopyModalText] = useState('')
  const [panicResponse, setPanicResponse] = useState<{ stalling_script: string[]; safety_tip: string } | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const logEndRef = useRef<HTMLDivElement>(null)

  // Auto-scroll war room logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [warRoomLogs])

  const parseManagerResponse = (rawResponse: string): ManagerVerdict | null => {
    try {
      // Try parsing as direct JSON first
      return JSON.parse(rawResponse)
    } catch {
      // Extract JSON from markdown code block
      const jsonMatch = rawResponse.match(/```json\n([\s\S]*?)\n```/)
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[1])
        // Handle nested structure
        if (parsed.result) {
          return parsed.result
        }
        return parsed
      }
      return null
    }
  }

  const addWarRoomLog = (agent: 'Manager' | 'Forensic' | 'Intelligence' | 'Response', message: string) => {
    const colors = {
      Manager: '#F59E0B',
      Forensic: '#3B82F6',
      Intelligence: '#A855F7',
      Response: '#10B981',
    }
    setWarRoomLogs(prev => [...prev, {
      timestamp: new Date().toLocaleTimeString(),
      agent,
      message,
      color: colors[agent],
    }])
  }

  const handleImageUpload = async (file: File) => {
    setUploadedImage(file)
    addWarRoomLog('Manager', `Screenshot uploaded: ${file.name}`)

    // Upload to agent system
    setUploadProgress(30)
    const uploadResult = await uploadFiles(file)
    setUploadProgress(100)

    if (uploadResult.success) {
      addWarRoomLog('Manager', `Image processed successfully`)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file && (file.type.startsWith('image/') || file.type === 'application/pdf')) {
      handleImageUpload(file)
    }
  }

  const handleAnalyze = async () => {
    if (!pastedText && !uploadedImage) return

    setAnalyzing(true)
    setVerdict(null)
    setWarRoomLogs([])

    addWarRoomLog('Manager', 'Analysis initiated - orchestrating agents...')

    try {
      let assetIds: string[] = []

      if (uploadedImage) {
        addWarRoomLog('Manager', 'Processing uploaded image...')
        const uploadResult = await uploadFiles(uploadedImage)
        if (uploadResult.success) {
          assetIds = uploadResult.asset_ids
          addWarRoomLog('Manager', 'Image uploaded to analysis system')
        }
      }

      addWarRoomLog('Forensic', 'Scanning for red flags and suspicious patterns...')
      addWarRoomLog('Intelligence', 'Matching against known scam database...')

      const message = pastedText || 'Analyze the uploaded image for potential scams or fraud.'

      const result = await callAIAgent(message, AGENT_IDS.manager, {
        assets: assetIds.length > 0 ? assetIds : undefined,
      })

      if (result.success) {
        addWarRoomLog('Manager', 'Forensic analysis complete')
        addWarRoomLog('Manager', 'Intelligence matching complete')
        addWarRoomLog('Manager', 'Aggregating findings...')

        // The Manager agent returns JSON directly in result
        let parsedVerdict: ManagerVerdict | null = null

        // Try multiple parsing strategies
        if (result.response.result) {
          // Strategy 1: result is already the verdict object
          if (result.response.result.verdict && result.response.result.confidence_score !== undefined) {
            parsedVerdict = result.response.result as ManagerVerdict
          }
          // Strategy 2: result has a nested verdict field
          else if (result.response.result.verdict && typeof result.response.result.verdict === 'string') {
            parsedVerdict = parseManagerResponse(result.response.result.verdict)
          }
          // Strategy 3: result.text or result.message contains JSON
          else if (result.response.result.text || result.response.result.message) {
            parsedVerdict = parseManagerResponse(result.response.result.text || result.response.result.message)
          }
          // Strategy 4: Parse the entire result as JSON string
          else {
            parsedVerdict = parseManagerResponse(JSON.stringify(result.response.result))
          }
        }

        if (parsedVerdict) {
          // HIGH-THREAT OVERRIDE: BNS 2024 Critical Patterns
          const inputText = (pastedText || '').toLowerCase()
          const hasCriticalThreat =
            inputText.includes('ipc 420') ||
            inputText.includes('digital arrest') ||
            inputText.includes('cyber arrest') ||
            (parsedVerdict.forensic_findings?.red_flags?.some(flag =>
              flag.description.toLowerCase().includes('ipc 420') ||
              flag.description.toLowerCase().includes('digital arrest') ||
              flag.description.toLowerCase().includes('cyber arrest')
            )) ||
            (parsedVerdict.intelligence_matches?.matched_patterns?.some(pattern =>
              pattern.pattern_name.toLowerCase().includes('ipc 420') ||
              pattern.pattern_name.toLowerCase().includes('digital arrest') ||
              pattern.pattern_name.toLowerCase().includes('cyber arrest')
            ))

          if (hasCriticalThreat) {
            parsedVerdict.verdict = 'RED'
            parsedVerdict.confidence_score = 98
            addWarRoomLog('Manager', 'CRITICAL THREAT DETECTED: IPC 420/Digital Arrest pattern - overriding to RED at 98% confidence')
          }

          setVerdict(parsedVerdict)

          // Extract war room logs from response
          if (parsedVerdict.war_room_log && Array.isArray(parsedVerdict.war_room_log)) {
            parsedVerdict.war_room_log.forEach((log: any) => {
              const logMessage = typeof log === 'string' ? log : (log.message || JSON.stringify(log))
              const logAgent = typeof log === 'object' && log.agent ? log.agent : 'Manager'
              addWarRoomLog(logAgent as any, logMessage)
            })
          }

          addWarRoomLog('Response', `Final verdict: ${parsedVerdict.verdict} (${Math.round(parsedVerdict.confidence_score || 0)}% confidence)`)

          // Use response_data from Manager if available, otherwise call Response Agent
          if (parsedVerdict.response_data && parsedVerdict.response_data.action_checklist) {
            const responseData = parsedVerdict.response_data
            setChecklist(responseData.action_checklist.map((item: string) => ({ text: item, checked: false })))
            setVerdict({ ...parsedVerdict })
            addWarRoomLog('Response', 'Action plan ready')
          } else if (parsedVerdict.verdict === 'RED' || parsedVerdict.verdict === 'YELLOW') {
            addWarRoomLog('Response', 'Generating action checklist...')

            // Fallback: Call Response Agent for detailed actions
            const responseResult = await callAIAgent(
              `Generate response for ${parsedVerdict.verdict} threat verdict with ${parsedVerdict.confidence_score}% confidence. Scam type: ${parsedVerdict.intelligence_matches?.scam_type || 'Unknown'}. Include cybercrime report in 1930 format and action checklist.`,
              AGENT_IDS.response
            )

            if (responseResult.success && responseResult.response.result) {
              const responseData = responseResult.response.result as ResponseAgentOutput
              if (responseData.action_checklist && Array.isArray(responseData.action_checklist)) {
                setChecklist(responseData.action_checklist.map((item: string) => ({ text: item, checked: false })))
              }

              // Store response data in verdict
              parsedVerdict.response_data = responseData
              setVerdict({ ...parsedVerdict })

              addWarRoomLog('Response', 'Action plan ready')
            }
          } else {
            setChecklist([{ text: 'No immediate action required - message appears safe', checked: false }])
          }
        } else {
          addWarRoomLog('Manager', 'Error: Failed to parse agent response')
          console.error('Raw response:', result)
        }
      } else {
        addWarRoomLog('Manager', `Error: ${result.error || 'API call failed'}`)
      }
    } catch (error) {
      addWarRoomLog('Manager', `Error: ${error instanceof Error ? error.message : 'Analysis failed'}`)
    } finally {
      setAnalyzing(false)
    }
  }

  const handlePanicModeAnalyze = async () => {
    if (!panicModeInput.trim()) return

    const threats: string[] = []
    const lowerInput = panicModeInput.toLowerCase()

    // Real-time pattern detection
    if (lowerInput.includes('police') || lowerInput.includes('arrest') || lowerInput.includes('warrant')) {
      threats.push('THREAT: Digital arrest scam pattern detected')
    }
    if (lowerInput.includes('otp') || lowerInput.includes('password')) {
      threats.push('THREAT: Credential theft attempt')
    }
    if (lowerInput.includes('transfer') || lowerInput.includes('payment') || lowerInput.includes('upi')) {
      threats.push('THREAT: Fraudulent payment request')
    }
    if (lowerInput.includes('kyc') || lowerInput.includes('account blocked')) {
      threats.push('THREAT: Fake KYC/account freeze scam')
    }
    if (lowerInput.includes('prize') || lowerInput.includes('lottery') || lowerInput.includes('won')) {
      threats.push('THREAT: Lottery/prize scam')
    }

    setPanicThreats(threats)
  }

  useEffect(() => {
    if (panicModeInput) {
      const timer = setTimeout(() => {
        handlePanicModeAnalyze()
      }, 500)
      return () => clearTimeout(timer)
    } else {
      setPanicThreats([])
    }
  }, [panicModeInput])

  // Real-time polling for panic response updates
  useEffect(() => {
    if (!panicMode || !panicModeInput.trim()) return

    const fetchPanicResponse = async () => {
      try {
        const result = await callAIAgent(
          `Generate real-time coaching for caller saying: "${panicModeInput}". Provide stalling_script array and safety_tip.`,
          AGENT_IDS.response
        )

        if (result.success && result.response.result) {
          const responseData = result.response.result
          if (responseData.stalling_script && responseData.safety_tip) {
            setPanicResponse({
              stalling_script: responseData.stalling_script,
              safety_tip: responseData.safety_tip,
            })
          }
        }
      } catch (error) {
        console.error('Panic response polling error:', error)
      }
    }

    // Initial fetch
    fetchPanicResponse()

    // Poll every 2.5 seconds
    const intervalId = setInterval(fetchPanicResponse, 2500)

    return () => clearInterval(intervalId)
  }, [panicMode, panicModeInput])

  const downloadReport = () => {
    if (!verdict?.response_data?.cybercrime_report) return

    const blob = new Blob([verdict.response_data.cybercrime_report], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `kavach-cybercrime-report-${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const copyReport = async () => {
    if (!verdict?.response_data?.cybercrime_report) return

    try {
      await navigator.clipboard.writeText(verdict.response_data.cybercrime_report)
      addWarRoomLog('Manager', 'Report copied to clipboard successfully')
    } catch (error) {
      // Fallback: Show in modal if clipboard API fails (permissions/security policy)
      if (error instanceof Error && error.name === 'NotAllowedError') {
        setCopyModalText(verdict.response_data.cybercrime_report)
        setShowCopyModal(true)
        addWarRoomLog('Manager', 'Clipboard access denied - showing report in modal')
      } else {
        // Generic fallback for any other error
        setCopyModalText(verdict.response_data.cybercrime_report)
        setShowCopyModal(true)
        addWarRoomLog('Manager', 'Copy failed - showing report in modal')
      }
    }
  }

  if (panicMode) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-blue-900 flex items-center justify-center p-4">
        <div className="max-w-4xl w-full space-y-6 animate-fade-in">
          {/* Header */}
          <div className="text-center space-y-4">
            <div className="flex items-center justify-center gap-3">
              <MdSecurity className="text-blue-300 text-6xl animate-pulse" />
              <h1 className="text-5xl font-bold text-white">PANIC MODE ACTIVE</h1>
            </div>
            <p className="text-2xl text-blue-200">Stay Calm - We&apos;re Here to Help</p>
            <Button
              onClick={() => setPanicMode(false)}
              variant="outline"
              className="bg-blue-700 hover:bg-blue-600 text-white border-blue-500"
            >
              Exit Panic Mode
            </Button>
          </div>

          {/* Caller Script Input */}
          <Card className="bg-blue-800/50 border-blue-600">
            <CardHeader>
              <CardTitle className="text-white text-xl">What is the caller saying?</CardTitle>
            </CardHeader>
            <CardContent>
              <Textarea
                value={panicModeInput}
                onChange={(e) => setPanicModeInput(e.target.value)}
                placeholder="Type what the caller is saying to you right now..."
                className="min-h-[120px] bg-white/10 text-white placeholder:text-blue-300 border-blue-500 text-lg"
              />
            </CardContent>
          </Card>

          {/* Detected Threats */}
          {panicThreats.length > 0 && (
            <Card className="bg-red-900/50 border-red-500 animate-shake">
              <CardHeader>
                <CardTitle className="text-red-200 flex items-center gap-2">
                  <MdWarning className="text-2xl" />
                  THREATS DETECTED
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {panicThreats.map((threat, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-red-100 text-lg font-semibold">
                    <FaExclamationTriangle className="text-red-400" />
                    {threat}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Stalling Scripts */}
          <Card className="bg-green-800/50 border-green-600">
            <CardHeader>
              <CardTitle className="text-white text-xl">Safe Responses (Read These Aloud)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {(panicResponse?.stalling_script || [
                "I need to verify this with my bank manager first before taking any action.",
                "Let me call the official helpline number to confirm this is legitimate.",
                "I will visit the branch in person tomorrow to handle this.",
                "I'm not comfortable sharing any information over the phone. Please send official documentation.",
                "I need to consult with my family/lawyer before proceeding.",
              ]).map((script, idx) => (
                <div key={idx} className="p-4 bg-white/10 rounded-lg border border-green-500">
                  <p className="text-white text-lg font-medium">{script}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Safety Tip */}
          {panicResponse?.safety_tip && (
            <Card className="bg-blue-800/50 border-blue-600">
              <CardHeader>
                <CardTitle className="text-white text-xl flex items-center gap-2">
                  <MdSecurity className="text-2xl" />
                  Safety Tip
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-blue-100 text-lg font-medium">{panicResponse.safety_tip}</p>
              </CardContent>
            </Card>
          )}

          {/* Evidence Collection */}
          <Card className="bg-yellow-800/50 border-yellow-600">
            <CardHeader>
              <CardTitle className="text-white text-xl">Collect Evidence Now</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                "Screenshot caller ID and call duration",
                "Note down the phone number calling you",
                "Record the conversation if possible (legal in most states)",
                "Save any messages or links they send",
                "Write down exact claims they're making",
              ].map((step, idx) => (
                <div key={idx} className="flex items-start gap-3 text-yellow-100">
                  <FaCheckCircle className="text-yellow-400 mt-1 flex-shrink-0" />
                  <p className="text-lg">{step}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Emergency Button */}
          <div className="fixed bottom-8 right-8">
            <a href="tel:1930">
              <Button
                size="lg"
                className="bg-red-600 hover:bg-red-700 text-white text-2xl px-8 py-8 rounded-full shadow-2xl animate-pulse-slow"
              >
                <FaPhone className="mr-3 text-3xl" />
                Call 1930 NOW
              </Button>
            </a>
          </div>

          {/* Confidence Meter */}
          {panicThreats.length > 0 && (
            <Card className="bg-black/30 border-red-500">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white font-semibold">Threat Level</span>
                  <span className="text-red-400 font-bold text-xl">
                    {panicThreats.length >= 3 ? 'CRITICAL' : panicThreats.length >= 2 ? 'HIGH' : 'MEDIUM'}
                  </span>
                </div>
                <div className="h-4 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      panicThreats.length >= 3 ? 'bg-red-600' : panicThreats.length >= 2 ? 'bg-orange-500' : 'bg-yellow-500'
                    }`}
                    style={{ width: `${Math.min(panicThreats.length * 30, 100)}%` }}
                  />
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#0A1628]" style={{
      backgroundImage: 'radial-gradient(circle at 1px 1px, rgba(255,255,255,0.05) 1px, transparent 0)',
      backgroundSize: '40px 40px'
    }}>
      {/* Shield Header */}
      <header className="border-b border-gray-800 bg-[#0A1628]/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <FaShieldAlt className="text-emerald-500 text-5xl animate-pulse-slow" />
              <div>
                <h1 className="text-3xl font-bold text-white tracking-wider">KAVACH</h1>
                <p className="text-sm text-gray-400">Scam Detection Shield</p>
              </div>
            </div>
            <Button
              onClick={() => setPanicMode(!panicMode)}
              variant={panicMode ? 'destructive' : 'outline'}
              size="lg"
              className={`${
                panicMode ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'
              } text-white border-none`}
            >
              <FaPhone className="mr-2" />
              {panicMode ? 'Exit' : 'Panic Mode'}
            </Button>
          </div>
        </div>
      </header>

      <div className="grid lg:grid-cols-[60%_40%] gap-6 p-6">
        {/* Left Column - Analysis */}
        <div className="space-y-6">
          {/* Verify Input Zone */}
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-2xl">Verify Suspicious Content</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Upload Zone */}
              <div
                onDrop={handleDrop}
                onDragOver={(e) => e.preventDefault()}
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-gray-700 hover:border-emerald-500 rounded-lg p-8 text-center cursor-pointer transition-all bg-gray-800/30 hover:bg-gray-800/50"
              >
                <FaUpload className="text-gray-500 text-5xl mx-auto mb-4" />
                <p className="text-gray-400 text-lg mb-2">
                  {uploadedImage ? uploadedImage.name : 'Drop screenshot here or click to upload'}
                </p>
                <p className="text-gray-600 text-sm">Supports PNG, JPG, PDF</p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*,application/pdf"
                  onChange={(e) => e.target.files?.[0] && handleImageUpload(e.target.files[0])}
                  className="hidden"
                />
              </div>

              {uploadProgress > 0 && uploadProgress < 100 && (
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              )}

              {/* Text Paste Field */}
              <div>
                <label className="text-gray-400 text-sm mb-2 block">Or paste suspicious message text</label>
                <Textarea
                  value={pastedText}
                  onChange={(e) => setPastedText(e.target.value)}
                  placeholder="Paste the suspicious message, email, or SMS content here..."
                  className="min-h-[150px] bg-gray-800 text-white placeholder:text-gray-600 border-gray-700"
                />
              </div>

              {/* Analyze Button */}
              <Button
                onClick={handleAnalyze}
                disabled={(!pastedText && !uploadedImage) || analyzing}
                size="lg"
                className="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-xl py-6"
              >
                {analyzing ? (
                  <>
                    <FaSpinner className="mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <MdSecurity className="mr-2" />
                    Analyze for Scams
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Verdict Display */}
          {verdict && (
            <>
              <Card className={`border-4 ${
                verdict.verdict === 'GREEN' ? 'border-emerald-500 bg-emerald-900/20' :
                verdict.verdict === 'YELLOW' ? 'border-amber-500 bg-amber-900/20' :
                'border-red-500 bg-red-900/20'
              }`}>
                <CardContent className="pt-8 text-center">
                  <div className="mb-6">
                    {verdict.verdict === 'GREEN' ? (
                      <MdCheckCircle className="text-emerald-500 text-9xl mx-auto animate-bounce-slow" />
                    ) : verdict.verdict === 'YELLOW' ? (
                      <MdWarning className="text-amber-500 text-9xl mx-auto animate-pulse" />
                    ) : (
                      <MdError className="text-red-500 text-9xl mx-auto animate-shake" />
                    )}
                  </div>
                  <h2 className={`text-7xl font-bold mb-4 ${
                    verdict.verdict === 'GREEN' ? 'text-emerald-400' :
                    verdict.verdict === 'YELLOW' ? 'text-amber-400' :
                    'text-red-400'
                  }`}>
                    {verdict.verdict === 'GREEN' ? 'SAFE' :
                     verdict.verdict === 'YELLOW' ? 'SUSPICIOUS' :
                     'SCAM DETECTED'}
                  </h2>

                  {/* Shield Meter */}
                  <div className="max-w-2xl mx-auto mb-6">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-gray-400">Confidence Score</span>
                      <span className="text-white font-bold text-2xl">{Math.round(verdict.confidence_score || 0)}%</span>
                    </div>
                    <div className="h-6 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-1500 ${
                          verdict.verdict === 'GREEN' ? 'bg-emerald-500' :
                          verdict.verdict === 'YELLOW' ? 'bg-amber-500' :
                          'bg-red-500'
                        }`}
                        style={{
                          width: `${Math.round(verdict.confidence_score || 0)}%`,
                          animation: 'fillMeter 1.5s ease-out'
                        }}
                      />
                    </div>
                  </div>

                  {verdict.final_recommendation && (
                  <p className="text-gray-300 text-lg max-w-3xl mx-auto">
                    {verdict.final_recommendation}
                  </p>
                  )}

                  <p className="text-gray-500 text-sm mt-2">
                    Total Confidence Score: {Math.round(verdict.confidence_score || 0)}%
                  </p>
                </CardContent>
              </Card>

              {/* Analysis Results */}
              <div className="space-y-4">
                {/* Red Flags */}
                {verdict.forensic_findings && (verdict.forensic_findings.red_flags?.length > 0 || (verdict.verdict !== 'GREEN' && verdict.forensic_findings.forensic_confidence > 0)) && (
                <Card className="bg-gray-900/50 border-gray-800">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-3 text-xl">
                      <FaExclamationTriangle className="text-red-500 text-2xl" />
                      Red Flags Detected ({verdict.forensic_findings.red_flags?.length || 0})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {verdict.forensic_findings.red_flags && verdict.forensic_findings.red_flags.length > 0 ? (
                      verdict.forensic_findings.red_flags.map((flag, idx) => (
                        <div key={idx} className="p-4 bg-gray-800/50 rounded-lg border-l-4 border-red-500 hover:bg-gray-800 transition-colors">
                          <div className="flex items-start justify-between gap-4 mb-2">
                            <p className="text-gray-200 flex-1 leading-relaxed">{flag.description}</p>
                            <button className={`px-4 py-1.5 rounded-full text-sm font-semibold whitespace-nowrap ${
                              flag.severity === 'HIGH' ? 'bg-red-600 text-white hover:bg-red-700' :
                              flag.severity === 'MEDIUM' ? 'bg-amber-500 text-white hover:bg-amber-600' :
                              'bg-yellow-500 text-gray-900 hover:bg-yellow-600'
                            } transition-colors`}>
                              {flag.severity}
                            </button>
                          </div>
                          <p className="text-gray-500 text-sm mt-2">Category: {flag.category}</p>
                        </div>
                      ))
                    ) : (
                      <div className="p-4 bg-gray-800/50 rounded-lg border-l-4 border-red-500">
                        <div className="flex items-start justify-between gap-4 mb-2">
                          <p className="text-gray-200 flex-1 leading-relaxed">
                            {verdict.final_recommendation || 'Forensic analysis detected suspicious patterns requiring investigation.'}
                          </p>
                          <button className="px-4 py-1.5 rounded-full text-sm font-semibold whitespace-nowrap bg-amber-500 text-white hover:bg-amber-600 transition-colors">
                            MEDIUM
                          </button>
                        </div>
                        <p className="text-gray-500 text-sm mt-2">Category: General Forensic Finding</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
                )}

                {/* Pattern Matches */}
                {verdict.intelligence_matches && (verdict.intelligence_matches.matched_patterns?.length > 0 || (verdict.verdict !== 'GREEN' && verdict.intelligence_matches.overall_pattern_confidence > 0)) && (
                <Card className="bg-gray-900/50 border-gray-800">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-3 text-xl">
                      <MdSecurity className="text-purple-500 text-2xl" />
                      Pattern Matches ({verdict.intelligence_matches.matched_patterns?.length || 0})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {verdict.intelligence_matches.scam_type && (
                    <div className="mb-4 p-4 bg-purple-900/30 rounded-lg border border-purple-600/50">
                      <p className="text-purple-200 font-semibold text-base">Scam Type: {verdict.intelligence_matches.scam_type}</p>
                    </div>
                    )}
                    {verdict.intelligence_matches.matched_patterns && verdict.intelligence_matches.matched_patterns.length > 0 ? (
                      verdict.intelligence_matches.matched_patterns.map((pattern, idx) => (
                        <div key={idx} className="p-4 bg-gray-800/50 rounded-lg border-l-4 border-purple-500 hover:bg-gray-800 transition-colors">
                          <div className="flex items-start justify-between gap-4 mb-2">
                            <p className="text-gray-200 flex-1 leading-relaxed">{pattern.pattern_name}</p>
                            <button className="px-4 py-1.5 rounded-full text-sm font-semibold bg-purple-600 text-white hover:bg-purple-700 transition-colors whitespace-nowrap">
                              {pattern.match_confidence}%
                            </button>
                          </div>
                          {pattern.source && (
                            <p className="text-gray-500 text-sm mt-2">Source: {pattern.source}</p>
                          )}
                          {pattern.evidence && (
                            <p className="text-gray-400 text-sm mt-1 italic">{pattern.evidence}</p>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="p-4 bg-gray-800/50 rounded-lg border-l-4 border-purple-500">
                        <div className="flex items-start justify-between gap-4 mb-2">
                          <p className="text-gray-200 flex-1 leading-relaxed">
                            {verdict.intelligence_matches.scam_type
                              ? `Intelligence database matched this content to known ${verdict.intelligence_matches.scam_type} patterns.`
                              : 'Intelligence analysis detected patterns matching known scam databases.'}
                          </p>
                          <button className="px-4 py-1.5 rounded-full text-sm font-semibold bg-purple-600 text-white hover:bg-purple-700 transition-colors whitespace-nowrap">
                            {Math.round(verdict.intelligence_matches.overall_pattern_confidence || 75)}%
                          </button>
                        </div>
                        <p className="text-gray-500 text-sm mt-2">Source: Intelligence Database</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
                )}

                {/* Action Checklist */}
                <Card className="bg-gray-900/50 border-gray-800">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center gap-2">
                      <FaCheckCircle className="text-green-500" />
                      Action Checklist
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {checklist.map((item, idx) => (
                      <div
                        key={idx}
                        onClick={() => {
                          const newChecklist = [...checklist]
                          newChecklist[idx].checked = !newChecklist[idx].checked
                          setChecklist(newChecklist)
                        }}
                        className="flex items-start gap-3 p-3 bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors"
                      >
                        <input
                          type="checkbox"
                          checked={item.checked}
                          onChange={() => {}}
                          className="mt-1 w-5 h-5 rounded"
                        />
                        <p className={`text-white flex-1 ${item.checked ? 'line-through opacity-50' : ''}`}>
                          {idx + 1}. {item.text}
                        </p>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                {/* Generate Report */}
                {(verdict.verdict === 'RED' || verdict.verdict === 'YELLOW') && verdict.response_data?.cybercrime_report && (
                  <Card className="bg-gray-900/50 border-gray-800">
                    <CardHeader>
                      <CardTitle className="text-white flex items-center justify-between">
                        <span>Cybercrime Report (1930 Format)</span>
                        <div className="flex gap-2">
                          <Button
                            onClick={copyReport}
                            variant="outline"
                            size="sm"
                            className="bg-gray-800 hover:bg-gray-700 text-white border-gray-700"
                          >
                            <FaCopy className="mr-2" />
                            Copy
                          </Button>
                          <Button
                            onClick={downloadReport}
                            variant="outline"
                            size="sm"
                            className="bg-gray-800 hover:bg-gray-700 text-white border-gray-700"
                          >
                            <FaDownload className="mr-2" />
                            Download
                          </Button>
                          <Button
                            onClick={() => setShowReport(!showReport)}
                            variant="outline"
                            size="sm"
                            className="bg-gray-800 hover:bg-gray-700 text-white border-gray-700"
                          >
                            {showReport ? <FaCompress /> : <FaExpand />}
                          </Button>
                        </div>
                      </CardTitle>
                    </CardHeader>
                    {showReport && (
                      <CardContent>
                        <pre className="text-gray-300 text-sm whitespace-pre-wrap bg-gray-800 p-4 rounded-lg overflow-x-auto">
                          {verdict.response_data.cybercrime_report}
                        </pre>
                      </CardContent>
                    )}
                  </Card>
                )}
              </div>
            </>
          )}
        </div>

        {/* Right Column - War Room */}
        <div className="lg:sticky lg:top-24 lg:h-[calc(100vh-8rem)]">
          <Card className="bg-gray-900/50 border-gray-800 h-full flex flex-col">
            <CardHeader>
              <CardTitle className="text-white text-xl flex items-center gap-2">
                <MdSecurity className="text-emerald-500 animate-pulse" />
                Agent War Room
              </CardTitle>
            </CardHeader>
            <CardContent className="flex-1 flex flex-col overflow-hidden">
              {/* Agent Status Indicators */}
              <div className="grid grid-cols-4 gap-2 mb-4">
                {[
                  { name: 'Manager', color: 'text-amber-500', active: analyzing },
                  { name: 'Forensic', color: 'text-blue-500', active: analyzing },
                  { name: 'Intel', color: 'text-purple-500', active: analyzing },
                  { name: 'Response', color: 'text-green-500', active: analyzing && (verdict?.verdict === 'RED' || verdict?.verdict === 'YELLOW') },
                ].map((agent, idx) => (
                  <div key={idx} className="text-center">
                    <FaShieldAlt className={`${agent.color} text-2xl mx-auto mb-1 ${agent.active ? 'animate-pulse' : ''}`} />
                    <p className="text-gray-400 text-xs">{agent.name}</p>
                  </div>
                ))}
              </div>

              {/* Live Log Stream */}
              <div className="flex-1 bg-black/30 rounded-lg p-4 overflow-y-auto space-y-2">
                {warRoomLogs.length === 0 ? (
                  <p className="text-gray-600 text-center mt-8">War room logs will appear here during analysis...</p>
                ) : (
                  warRoomLogs.map((log, idx) => (
                    <div key={idx} className="animate-fade-in">
                      <div className="flex items-start gap-2 text-sm">
                        <span className="text-gray-600 flex-shrink-0">[{log.timestamp}]</span>
                        <span className="font-semibold flex-shrink-0" style={{ color: log.color }}>
                          {log.agent}:
                        </span>
                        <span className="text-gray-300">{log.message}</span>
                      </div>
                    </div>
                  ))
                )}
                <div ref={logEndRef} />
              </div>

              {/* Confidence Timeline */}
              {verdict && (
                <div className="mt-4 pt-4 border-t border-gray-800">
                  <p className="text-gray-400 text-sm mb-2">Analysis Complete</p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          verdict.verdict === 'GREEN' ? 'bg-emerald-500' :
                          verdict.verdict === 'YELLOW' ? 'bg-amber-500' :
                          'bg-red-500'
                        }`}
                        style={{ width: `${Math.round(verdict.confidence_score || 0)}%` }}
                      />
                    </div>
                    <span className="text-white font-bold">{Math.round(verdict.confidence_score || 0)}%</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <style jsx>{`
        @keyframes fillMeter {
          from { width: 0%; }
        }
        @keyframes fade-in {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          25% { transform: translateX(-5px); }
          75% { transform: translateX(5px); }
        }
        @keyframes pulse-slow {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
        @keyframes bounce-slow {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-10px); }
        }
        .animate-fade-in {
          animation: fade-in 0.3s ease-out;
        }
        .animate-shake {
          animation: shake 0.5s ease-in-out infinite;
        }
        .animate-pulse-slow {
          animation: pulse-slow 3s ease-in-out infinite;
        }
        .animate-bounce-slow {
          animation: bounce-slow 2s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}
