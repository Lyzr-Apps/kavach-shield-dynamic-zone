// TypeScript interfaces based on actual agent response structures

export interface RedFlag {
  description: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH'
  severity_score: number
  category: string
}

export interface ForensicFindings {
  red_flags: RedFlag[]
  total_severity_score: number
  forensic_confidence: number
}

export interface MatchedPattern {
  pattern_name: string
  match_confidence: number
  source: string
}

export interface IntelligenceMatches {
  matched_patterns: MatchedPattern[]
  scam_type: string
  overall_pattern_confidence: number
}

export interface ResponseAgentOutput {
  action_checklist: string[]
  cybercrime_report?: string
  guidance_script?: string | null
  evidence_collection_steps: string[]
  threat_level?: string
  reassurance_message?: string | null
}

export interface ManagerVerdict {
  verdict: 'GREEN' | 'YELLOW' | 'RED'
  confidence_score: number
  forensic_findings: ForensicFindings
  intelligence_matches: IntelligenceMatches
  final_recommendation: string
  war_room_log?: string[]
  response_data?: ResponseAgentOutput
}

export interface WarRoomLogEntry {
  timestamp: string
  agent: 'Manager' | 'Forensic' | 'Intelligence' | 'Response'
  message: string
  color: string
}

export interface ChecklistItem {
  text: string
  checked: boolean
}
