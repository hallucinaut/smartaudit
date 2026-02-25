// Package audit provides smart contract security auditing capabilities.
package audit

import (
	"fmt"
	"regexp"
	"strings"
)

// Vulnerability represents a detected vulnerability.
type Vulnerability struct {
	ID         string
	Name       string
	Type       string
	Severity   string
	CWE        string
	CVE        string
	Location   string
	Line       int
	Description string
	Recommendation string
	Evidence   string
}

// AuditResult contains audit results.
type AuditResult struct {
	ContractName    string
	IsSecure        bool
	Vulnerabilities []Vulnerability
	RiskScore       float64
	AnalysisTime    string
}

// Auditor audits smart contracts for security issues.
type Auditor struct {
	rules []Rule
}

// Rule defines a security rule.
type Rule struct {
	ID         string
	Name       string
	Pattern    *regexp.Regexp
	Severity   string
	CWE        string
	Category   string
	Description string
}

// ContractInfo contains contract information.
type ContractInfo struct {
	Name    string
	Version string
	Network string
	Author  string
}

// NewAuditor creates a new smart contract auditor.
func NewAuditor() *Auditor {
	return &Auditor{
		rules: []Rule{
			{
				ID:       "SC-001",
				Name:     "Reentrancy Attack",
				Pattern:  regexp.MustCompile(`(?i)(external\.call|call\(|send\(|transfer\()(.*){[^}]*function`),
				Severity: "CRITICAL",
				CWE:      "CWE-863",
				Category: "reentrancy",
				Description: "Reentrancy vulnerability detected - external call before state update",
			},
			{
				ID:       "SC-002",
				Name:     "Integer Overflow",
				Pattern:  regexp.MustCompile(`(?i)(\+\+|--|+=|-=)\s*\w+[^;]*;`),
				Severity: "HIGH",
				CWE:      "CWE-190",
				Category: "arithmetic",
				Description: "Potential integer overflow/underflow detected",
			},
			{
				ID:       "SC-003",
				Name:     "Unchecked Return",
				Pattern:  regexp.MustCompile(`(?i)(external\.call|call\(|staticcall\()(.*){[^}]*}`),
				Severity: "HIGH",
				CWE:      "CWE-252",
				Category: "validation",
				Description: "Return value of external call not checked",
			},
			{
				ID:       "SC-004",
				Name:     "Access Control",
				Pattern:  regexp.MustCompile(`(?i)function\s+\w+\s*\(.*\)\s*public\s*{`),
				Severity: "MEDIUM",
				CWE:      "CWE-284",
				Category: "access",
				Description: "Public function without access control",
			},
			{
				ID:       "SC-005",
				Name:     "Timestamp Dependence",
				Pattern:  regexp.MustCompile(`(?i)(block\.timestamp|now|block\.delay)`),
				Severity: "MEDIUM",
				CWE:      "CWE-835",
				Category: "time",
				Description: "Timestamp dependency detected",
			},
			{
				ID:       "SC-006",
				Name:     "Denial of Service",
				Pattern:  regexp.MustCompile(`(?i)(for\s*\([^)]*<\s*\w+)\s*\{`),
				Severity: "HIGH",
				CWE:      "CWE-400",
				Category: "dos",
				Description: "Potential DoS vulnerability in loop",
			},
			{
				ID:       "SC-007",
				Name:     "Delegatecall to Untrusted",
				Pattern:  regexp.MustCompile(`(?i)delegatecall\s*\([^)]*\)`),
				Severity: "CRITICAL",
				CWE:      "CWE-841",
				Category: "delegate",
				Description: "Unsafe delegatecall detected",
			},
			{
				ID:       "SC-008",
				Name:     "Unprotected Mint",
				Pattern:  regexp.MustCompile(`(?i)(mint|createToken)\s*\([^)]*\)\s*{`),
				Severity: "HIGH",
				CWE:      "CWE-269",
				Category: "minting",
				Description: "Mint function without access control",
			},
			{
				ID:       "SC-009",
				Name:     "Shadowing Variable",
				Pattern:  regexp.MustCompile(`(?i)(uint|int|address|bool)\s+\w+\s*=`),
				Severity: "LOW",
				CWE:      "CWE-543",
				Category: "variable",
				Description: "Potential variable shadowing",
			},
			{
				ID:       "SC-010",
				Name:     "Gas Limit",
				Pattern:  regexp.MustCompile(`(?i)(gaslimit|gas\.limit|\.gas\(\))`),
				Severity: "MEDIUM",
				CWE:      "CWE-409",
				Category: "gas",
				Description: "Gas limit manipulation detected",
			},
		},
	}
}

// Audit audits a smart contract.
func (a *Auditor) Audit(contractCode string, info *ContractInfo) *AuditResult {
	result := &AuditResult{
		ContractName:   info.Name,
		IsSecure:       true,
		Vulnerabilities: make([]Vulnerability, 0),
		RiskScore:      0.0,
		AnalysisTime:   "2024-02-25",
	}

	for _, rule := range a.rules {
		vulns := a.checkRule(contractCode, rule)
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	// Calculate risk score
	result.RiskScore = a.calculateRiskScore(result.Vulnerabilities)
	result.IsSecure = result.RiskScore < 0.3

	return result
}

// checkRule checks a single rule.
func (a *Auditor) checkRule(contractCode string, rule Rule) []Vulnerability {
	var vulns []Vulnerability

	lines := strings.Split(contractCode, "\n")
	for i, line := range lines {
		if rule.Pattern.MatchString(line) {
			vuln := Vulnerability{
				ID:         rule.ID,
				Name:       rule.Name,
				Type:       rule.Category,
				Severity:   rule.Severity,
				CWE:        rule.CWE,
				Location:   "line " + string(rune(i+49)),
				Line:       i + 1,
				Description: rule.Description,
				Evidence:   strings.TrimSpace(line)[:min(len(strings.TrimSpace(line)), 80)],
			}
			vuln.Recommendation = a.getRecommendation(rule)
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// getRecommendation returns recommendation for a rule.
func (a *Auditor) getRecommendation(rule Rule) string {
	recommendations := map[string]string{
		"reentrancy": "Use checks-effects-interactions pattern",
		"arithmetic": "Use SafeMath library or Solidity 0.8+",
		"validation": "Check return values of external calls",
		"access":     "Implement proper access control modifiers",
		"time":       "Avoid timestamp for critical logic",
		"dos":        "Use gas-limited loops or batch processing",
		"delegate":   "Validate delegatecall targets carefully",
		"minting":    "Add access control to mint function",
		"variable":   "Avoid variable shadowing",
		"gas":        "Use explicit gas limits",
	}

	if rec, exists := recommendations[rule.Category]; exists {
		return rec
	}
	return "Review and fix security issue"
}

// calculateRiskScore calculates risk score.
func (a *Auditor) calculateRiskScore(vulns []Vulnerability) float64 {
	if len(vulns) == 0 {
		return 0.0
	}

	score := 0.0
	for _, vuln := range vulns {
		switch vuln.Severity {
		case "CRITICAL":
			score += 0.4
		case "HIGH":
			score += 0.25
		case "MEDIUM":
			score += 0.1
		case "LOW":
			score += 0.05
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

// min returns minimum of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetSeverity returns severity from score.
func GetSeverity(score float64) string {
	if score >= 0.8 {
		return "CRITICAL"
	} else if score >= 0.6 {
		return "HIGH"
	} else if score >= 0.4 {
		return "MEDIUM"
	} else if score >= 0.2 {
		return "LOW"
	}
	return "MINIMAL"
}

// GenerateReport generates audit report.
func GenerateReport(result *AuditResult) string {
	var report string

	report += "=== Smart Contract Security Audit Report ===\n\n"
	report += "Contract: " + result.ContractName + "\n"
	report += "Risk Score: " + fmt.Sprintf("%.0f%%", result.RiskScore*100) + "%\n"
	report += "Status: " + boolToString(result.IsSecure) + "\n\n"

	if len(result.Vulnerabilities) > 0 {
		report += "Vulnerabilities Found: " + string(rune(len(result.Vulnerabilities)+48)) + "\n\n"
		for i, vuln := range result.Vulnerabilities {
			report += "[" + string(rune(i+49)) + "] " + vuln.Name + "\n"
			report += "    ID: " + vuln.ID + "\n"
			report += "    Severity: " + vuln.Severity + "\n"
			report += "    CWE: " + vuln.CWE + "\n"
			report += "    Location: " + vuln.Location + "\n"
			report += "    Description: " + vuln.Description + "\n"
			report += "    Recommendation: " + vuln.Recommendation + "\n\n"
		}
	} else {
		report += "✓ No vulnerabilities detected\n"
	}

	return report
}

// boolToString converts bool to string.
func boolToString(b bool) string {
	if b {
		return "Secure"
	}
	return "Vulnerable"
}