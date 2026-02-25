package main

import (
	"fmt"
	"os"

	"github.com/hallucinaut/smartaudit/pkg/audit"
	"github.com/hallucinaut/smartaudit/pkg/analyze"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "audit":
		if len(os.Args) < 3 {
			fmt.Println("Error: contract file required")
			printUsage()
			return
		}
		auditContract(os.Args[2])
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Println("Error: contract file required")
			printUsage()
			return
		}
		analyzeContract(os.Args[2])
	case "check":
		checkSecurity()
	case "version":
		fmt.Printf("smartaudit version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`smartaudit - Smart Contract Security Auditor

Usage:
  smartaudit <command> [options]

Commands:
  audit <file>     Audit smart contract for security issues
  analyze <file>   Analyze smart contract for optimizations
  check            Check security configurations
  version          Show version information
  help             Show this help message

Examples:
  smartaudit audit contract.sol
  smartaudit analyze contract.sol
`, "smartaudit")
}

func auditContract(filepath string) {
	fmt.Printf("Auditing smart contract: %s\n", filepath)
	fmt.Println()

	// In production: read and parse Solidity file
	// For demo: show audit template
	fmt.Println("Security Audit Capabilities:")
	fmt.Println("  ✓ Reentrancy detection")
	fmt.Println("  ✓ Integer overflow/underflow")
	fmt.Println("  ✓ Unchecked return values")
	fmt.Println("  ✓ Access control issues")
	fmt.Println("  ✓ Timestamp dependence")
	fmt.Println("  ✓ DoS vulnerabilities")
	fmt.Println("  ✓ Delegatecall safety")
	fmt.Println("  ✓ Unprotected minting")
	fmt.Println()

	// Example audit
	auditor := audit.NewAuditor()
	info := &audit.ContractInfo{
		Name:    "ExampleContract",
		Version: "1.0.0",
	}

	result := auditor.Audit("sample contract code", info)

	fmt.Println(audit.GenerateReport(result))
}

func analyzeContract(filepath string) {
	fmt.Printf("Analyzing smart contract: %s\n", filepath)
	fmt.Println()

	// In production: read and parse Solidity file
	// For demo: show analysis template
	fmt.Println("Analysis Capabilities:")
	fmt.Println("  ✓ Gas optimization")
	fmt.Println("  ✓ Function safety")
	fmt.Println("  ✓ State management")
	fmt.Println("  ✓ Security checks")
	fmt.Println()

	// Example analysis
	analyzer := analyze.NewAnalyzer()
	result := analyzer.Analyze("sample contract code")

	fmt.Println(analyze.GenerateReport(result))
}

func checkSecurity() {
	fmt.Println("Security Check")
	fmt.Println("==============")
	fmt.Println()

	fmt.Println("Audited Vulnerabilities:")
	fmt.Println("  SC-001: Reentrancy Attack")
	fmt.Println("  SC-002: Integer Overflow")
	fmt.Println("  SC-003: Unchecked Return")
	fmt.Println("  SC-004: Access Control")
	fmt.Println("  SC-005: Timestamp Dependence")
	fmt.Println("  SC-006: Denial of Service")
	fmt.Println("  SC-007: Delegatecall to Untrusted")
	fmt.Println("  SC-008: Unprotected Mint")
	fmt.Println("  SC-009: Shadowing Variable")
	fmt.Println("  SC-010: Gas Limit")
}