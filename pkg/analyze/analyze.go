// Package analyze provides smart contract analysis capabilities.
package analyze

import (
	"regexp"
	"strings"
)

// AnalysisType represents a type of analysis.
type AnalysisType string

const (
	TypeGasOptimization AnalysisType = "gas-optimization"
	TypeFunctionSafety  AnalysisType = "function-safety"
	TypeStateManagement AnalysisType = "state-management"
	TypeSecurityCheck   AnalysisType = "security-check"
)

// AnalysisResult contains analysis results.
type AnalysisResult struct {
	Type        AnalysisType
	Score       float64
	Issues      []Issue
	Recommendations []string
}

// Issue represents an issue found during analysis.
type Issue struct {
	Severity  string
	Message   string
	Line      int
	Solution  string
}

// Analyzer analyzes smart contracts.
type Analyzer struct {
	patterns map[AnalysisType][]Pattern
}

// Pattern defines an analysis pattern.
type Pattern struct {
	Name     string
	Regex    *regexp.Regexp
	Weight   float64
	Category string
}

// NewAnalyzer creates a new smart contract analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		patterns: map[AnalysisType][]Pattern{
			TypeGasOptimization: {
				{
					Name:  "Unnecessary Storage Write",
					Regex: regexp.MustCompile(`(?i)state\.\w+\s*=\s*\w+;`),
					Weight: 0.3,
				},
				{
					Name:  "Array Length Check",
					Regex: regexp.MustCompile(`(?i)array\.length`),
					Weight: 0.2,
				},
				{
					Name:  "Loop Optimization",
					Regex: regexp.MustCompile(`(?i)for\s*\([^)]*\)\s*{`),
					Weight: 0.4,
				},
			},
			TypeFunctionSafety: {
				{
					Name:  "External Call",
					Regex: regexp.MustCompile(`(?i)(external\.call|call\()`),
					Weight: 0.5,
				},
				{
					Name:  "Reentrancy Guard",
					Regex: regexp.MustCompile(`(?i)nonReentrant`),
					Weight: 0.3,
				},
			},
			TypeStateManagement: {
				{
					Name:  "State Update",
					Regex: regexp.MustCompile(`(?i)state\.\w+\s*=`),
					Weight: 0.4,
				},
				{
					Name:  "Event Emission",
					Regex: regexp.MustCompile(`(?i)emit\s+\w+\s*\(`),
					Weight: 0.2,
				},
			},
			TypeSecurityCheck: {
				{
					Name:  "Access Control",
					Regex: regexp.MustCompile(`(?i)(onlyOwner|onlyAdmin|modifier)\s*\(.*\)\s*{`),
					Weight: 0.6,
				},
				{
					Name:  "Validation",
					Regex: regexp.MustCompile(`(?i)require\s*\(`),
					Weight: 0.4,
				},
			},
		},
	}
}

// Analyze analyzes a smart contract.
func (a *Analyzer) Analyze(contractCode string) *AnalysisResult {
	results := make(map[AnalysisType]*AnalysisResult)

	for _, atype := range []AnalysisType{
		TypeGasOptimization,
		TypeFunctionSafety,
		TypeStateManagement,
		TypeSecurityCheck,
	} {
		results[atype] = a.analyzeType(contractCode, atype)
	}

	return a.combineResults(results)
}

// analyzeType analyzes a specific type.
func (a *Analyzer) analyzeType(contractCode string, atype AnalysisType) *AnalysisResult {
	result := &AnalysisResult{
		Type:        atype,
		Score:       1.0,
		Issues:      make([]Issue, 0),
		Recommendations: make([]string, 0),
	}

	patterns := a.patterns[atype]
	for _, pattern := range patterns {
		if pattern.Regex.MatchString(contractCode) {
			issue := Issue{
				Severity: "MEDIUM",
				Message:  pattern.Name,
				Solution: "Optimize or review " + pattern.Name,
			}
			result.Issues = append(result.Issues, issue)
			result.Score -= pattern.Weight
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result
}

// combineResults combines all analysis results.
func (a *Analyzer) combineResults(results map[AnalysisType]*AnalysisResult) *AnalysisResult {
	totalScore := 0.0
	totalIssues := 0
	allRecommendations := make(map[string]bool)

	for _, result := range results {
		totalScore += result.Score
		totalIssues += len(result.Issues)

		for _, rec := range result.Recommendations {
			allRecommendations[rec] = true
		}
	}

	avgScore := totalScore / float64(len(results))

	return &AnalysisResult{
		Type:        "combined",
		Score:       avgScore,
		Issues:      make([]Issue, totalIssues),
		Recommendations: make([]string, 0),
	}
}

// GenerateReport generates analysis report.
func GenerateReport(result *AnalysisResult) string {
	var report string

	report += "=== Smart Contract Analysis Report ===\n\n"
	report += "Analysis Score: " + string(rune(int(result.Score*100)+48)) + "%\n"
	report += "Issues Found: " + string(rune(len(result.Issues)+48)) + "\n\n"

	if len(result.Issues) > 0 {
		report += "Issues:\n"
		for i, issue := range result.Issues {
			report += "[" + string(rune(i+49)) + "] " + issue.Message + "\n"
			report += "    Severity: " + issue.Severity + "\n"
			report += "    Solution: " + issue.Solution + "\n\n"
		}
	}

	return report
}

// GetAnalysisType returns analysis type.
func GetAnalysisType(atype AnalysisType) string {
	switch atype {
	case TypeGasOptimization:
		return "Gas Optimization"
	case TypeFunctionSafety:
		return "Function Safety"
	case TypeStateManagement:
		return "State Management"
	case TypeSecurityCheck:
		return "Security Check"
	default:
		return "Combined"
	}
}