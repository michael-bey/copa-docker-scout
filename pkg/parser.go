package parser

import (
	"encoding/json"
	"fmt"
	"strings"
)

func isValidPackage(pkgName string, description string, severity string) bool {
	// Skip Python packages and other non-OS packages
	if strings.HasPrefix(pkgName, "python") || strings.HasPrefix(pkgName, "pip") {
		return false
	}

	// Skip packages with "REJECTED" in description or unknown/low severity
	if strings.Contains(description, "REJECTED") ||
		strings.Contains(description, "unimportant") ||
		severity == "Unknown" ||
		severity == "Low" {
		return false
	}

	return true
}

func extractPackageName(pkgString string) string {
	// Remove URL parameters if present
	if idx := strings.Index(pkgString, "?"); idx != -1 {
		pkgString = pkgString[:idx]
	}

	// Split by @ to separate package name and version
	parts := strings.Split(pkgString, "@")
	if len(parts) < 1 {
		return ""
	}

	// Split by / to get components
	components := strings.Split(parts[0], "/")
	if len(components) < 3 {
		return ""
	}

	// The package name is the last component
	pkgName := components[len(components)-1]

	// Handle special characters in Debian package names
	pkgName = strings.ReplaceAll(pkgName, "%2B", "+")
	pkgName = strings.ReplaceAll(pkgName, "%2F", "/")
	pkgName = strings.ReplaceAll(pkgName, "%2E", ".")

	return pkgName
}

func parse(report []byte) ([]string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(report, &data); err != nil {
		return nil, fmt.Errorf("failed to parse report: %v", err)
	}

	vulnerabilities, ok := data["vulnerabilities"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid report format: vulnerabilities not found")
	}

	processedPackages := make(map[string]bool)
	var commands []string

	for _, v := range vulnerabilities {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		description, _ := vuln["description"].(string)
		severity, _ := vuln["severity"].(string)

		location, ok := vuln["location"].(map[string]interface{})
		if !ok {
			continue
		}

		dependency, ok := location["dependency"].(map[string]interface{})
		if !ok {
			continue
		}

		pkg, ok := dependency["package"].(map[string]interface{})
		if !ok {
			continue
		}

		pkgName, ok := pkg["name"].(string)
		if !ok {
			continue
		}

		// Extract the base package name
		basePkg := extractPackageName(pkgName)
		if basePkg == "" {
			continue
		}

		// Skip if we've already processed this package
		if processedPackages[basePkg] {
			continue
		}

		// Skip if not a valid package
		if !isValidPackage(basePkg, description, severity) {
			continue
		}

		// Add the package to the list of processed packages
		processedPackages[basePkg] = true

		// Add the apt-get install command
		commands = append(commands, fmt.Sprintf("apt-get install -y %s", basePkg))
	}

	return commands, nil
}
