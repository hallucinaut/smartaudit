# smartaudit - Smart Contract Security Auditor

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Comprehensive smart contract security auditing for blockchain applications.**

Identify vulnerabilities, analyze code quality, and ensure smart contract security before deployment.

## 🚀 Features

- **Multi-Vector Security Analysis**: Detect reentrancy, overflow, access control, and more
- **CWE/Standard Compliance**: Map vulnerabilities to CWE standards
- **Gas Optimization**: Identify gas inefficiencies
- **Function Safety**: Check external calls and state management
- **Security Scoring**: Calculate risk scores for contracts
- **Comprehensive Reporting**: Detailed audit reports with recommendations

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/smartaudit.git
cd smartaudit
go build -o smartaudit ./cmd/smartaudit
sudo mv smartaudit /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/smartaudit/cmd/smartaudit@latest
```

## 🎯 Usage

### Audit Contract

```bash
# Audit smart contract for vulnerabilities
smartaudit audit contract.sol

# Analyze for optimizations
smartaudit analyze contract.sol
```

### Check Security

```bash
# Check security configurations
smartaudit check
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/smartaudit/pkg/audit"
)

func main() {
    auditor := audit.NewAuditor()
    
    // Audit contract
    info := &audit.ContractInfo{
        Name:    "MyContract",
        Version: "1.0.0",
    }
    
    result := auditor.Audit(contractCode, info)
    
    fmt.Printf("Contract: %s\n", result.ContractName)
    fmt.Printf("Risk Score: %.0f%%\n", result.RiskScore*100)
    
    for _, vuln := range result.Vulnerabilities {
        fmt.Printf("Vulnerability: %s (%s)\n", vuln.Name, vuln.Severity)
    }
}
```

## 🔍 Vulnerabilities Detected

### Critical Severity

| ID | Name | CWE | Description |
|----|------|-----|-------------|
| SC-001 | Reentrancy Attack | CWE-863 | External call before state update |
| SC-007 | Delegatecall to Untrusted | CWE-841 | Unsafe delegatecall usage |

### High Severity

| ID | Name | CWE | Description |
|----|------|-----|-------------|
| SC-002 | Integer Overflow | CWE-190 | Arithmetic overflow/underflow |
| SC-003 | Unchecked Return | CWE-252 | Missing return value checks |
| SC-006 | Denial of Service | CWE-400 | Gas-limited loop issues |
| SC-008 | Unprotected Mint | CWE-269 | Missing access control |

### Medium Severity

| ID | Name | CWE | Description |
|----|------|-----|-------------|
| SC-004 | Access Control | CWE-284 | Missing access modifiers |
| SC-005 | Timestamp Dependence | CWE-835 | Block time manipulation |
| SC-010 | Gas Limit | CWE-409 | Gas limit issues |

### Low Severity

| ID | Name | CWE | Description |
|----|------|-----|-------------|
| SC-009 | Shadowing Variable | CWE-543 | Variable shadowing |

## 📊 Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 0.0-0.2 | MINIMAL | Safe to deploy |
| 0.2-0.4 | LOW | Minor improvements needed |
| 0.4-0.6 | MEDIUM | Address before deployment |
| 0.6-0.8 | HIGH | Critical fixes required |
| 0.8-1.0 | CRITICAL | Block deployment |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/audit -run TestAuditContract
```

## 📋 Example Output

```
Auditing smart contract: contract.sol

=== Smart Contract Security Audit Report ===

Contract: ExampleContract
Risk Score: 45%
Status: Vulnerable

Vulnerabilities Found: 3

[1] Reentrancy Attack
    ID: SC-001
    Severity: CRITICAL
    CWE: CWE-863
    Location: line 42
    Description: Reentrancy vulnerability detected
    Recommendation: Use checks-effects-interactions pattern

[2] Integer Overflow
    ID: SC-002
    Severity: HIGH
    CWE: CWE-190
    Location: line 156
    Description: Potential integer overflow detected
    Recommendation: Use SafeMath library

[3] Unchecked Return
    ID: SC-003
    Severity: HIGH
    CWE: CWE-252
    Location: line 89
    Description: Return value not checked
    Recommendation: Check return values

⚠️ Contract requires fixes before deployment
```

## 🔒 Security Use Cases

- **DeFi Protocol Audits**: Secure decentralized finance contracts
- **NFT Smart Contracts**: Protect minting and trading
- **Token Contracts**: Ensure token security
- **DAO Contracts**: Secure governance mechanisms
- **Bridge Contracts**: Protect cross-chain transfers

## 🛡️ Best Practices

1. **Always audit before deployment**
2. **Use established libraries** (OpenZeppelin, etc.)
3. **Implement reentrancy guards**
4. **Use SafeMath or Solidity 0.8+**
5. **Test thoroughly on testnet**
6. **Consider third-party audits**
7. **Monitor for vulnerabilities post-deployment**

## 🏗️ Architecture

```
smartaudit/
├── cmd/
│   └── smartaudit/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── audit/
│   │   ├── audit.go        # Security auditing
│   │   └── audit_test.go   # Unit tests
│   └── analyze/
│       ├── analyze.go      # Contract analysis
│       └── analyze_test.go # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Solidity security community
- Smart contract auditors
- Blockchain security researchers

## 🔗 Resources

- [SWC Registry](https://swcregistry.io/)
- [Smart Contract Weakness Classification](https://github.com/SmartContractSecurity/SWC-Registry)
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security](https://blog.openzeppelin.com/security/)

---

**Built with GPU by [hallucinaut](https://github.com/hallucinaut)**