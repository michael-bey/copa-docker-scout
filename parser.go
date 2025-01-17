package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

var packageMappings map[string]string

func init() {
	// Initialize package name mappings
	packageMappings = map[string]string{
		"libwebp":    "libwebp6",
		"openssl":    "openssl",
		"glibc":      "libc6",
		"shadow":     "shadow",
		"tiff":       "libtiff5",
		"tar":        "tar",
		"gcc-9":      "gcc-9",
		"gcc-10":     "gcc-10",
		"curl":       "curl",
		"util-linux": "util-linux",
		"gnutls28":   "libgnutls30",
		"nghttp2":    "libnghttp2-14",
		"systemd":    "systemd",
		"libx11":     "libx11-6",
		"libxpm":     "libxpm4",
		"gnupg2":     "gnupg2",
		"libxml2":    "libxml2",
		"krb5":       "libkrb5-3",
		"perl":       "perl",
		"libssh2":    "libssh2-1",
		"libtirpc":   "libtirpc3",
		"expat":      "libexpat1",
		"ncurses":    "libncurses6",
		"libxslt":    "libxslt1.1",
		"libtasn1-6": "libtasn1-6",
		"zlib":       "zlib1g",
		"freetype":   "libfreetype6",
		"pcre2":      "libpcre2-8-0",
		"libsepol":   "libsepol1",
	}
}

func parse(input []byte) (string, error) {
	var report DockerScoutReport
	if err := json.Unmarshal(input, &report); err != nil {
		return "", fmt.Errorf("failed to unmarshal report: %v", err)
	}

	if len(report.Vulnerabilities) == 0 {
		log.Printf("No vulnerabilities found")
		return "", nil
	}

	// Initialize update manifest
	manifest := UpdateManifest{
		APIVersion: "v1alpha1",
		Metadata: Metadata{
			Config: Config{
				Arch: "amd64", // Default to amd64 as Docker Scout doesn't provide arch info
			},
		},
		Updates: make(UpdatePackages, 0),
	}

	// Track processed packages to avoid duplicates
	processedPackages := make(map[string]bool)

	for _, vuln := range report.Vulnerabilities {
		log.Printf("Processing vulnerability: %s", vuln.CVE)

		if vuln.Description != "" && (strings.Contains(vuln.Description, "<no-dsa>") ||
			strings.Contains(vuln.Description, "<unfixed>") ||
			strings.Contains(vuln.Description, "REJECT") ||
			strings.Contains(vuln.Description, "<ignored>")) {
			log.Printf("Skipping vulnerability %s due to description", vuln.CVE)
			continue
		}

		// Set OS info if not already set
		if manifest.Metadata.OS.Type == "" && vuln.Location.OperatingSystem != "" {
			parts := strings.Fields(vuln.Location.OperatingSystem)
			if len(parts) >= 2 {
				manifest.Metadata.OS.Type = parts[0]
				manifest.Metadata.OS.Version = parts[1]
			}
		}

		pkgUrl := vuln.Location.Dependency.Package.Name
		if pkgUrl == "" {
			continue
		}

		// Parse package name from pkg:deb/debian/packagename format
		parts := strings.Split(pkgUrl, "/")
		if len(parts) < 3 {
			log.Printf("Invalid package URL format: %s", pkgUrl)
			continue
		}

		// Get the last part which contains packagename[@version][?params]
		pkgName := parts[len(parts)-1]
		if idx := strings.Index(pkgName, "@"); idx != -1 {
			pkgName = pkgName[:idx]
		}
		if idx := strings.Index(pkgName, "?"); idx != -1 {
			pkgName = pkgName[:idx]
		}

		if processedPackages[pkgName] {
			continue
		}

		mappedPkg := mapToDebianPackage(pkgName)
		if mappedPkg != "" {
			// Extract version information
			installedVersion := vuln.Location.Dependency.Version
			fixedVersion := ""

			// Try to extract fixed version from solution
			if vuln.Solution != "" {
				if strings.HasPrefix(vuln.Solution, "Upgrade") {
					parts := strings.Split(vuln.Solution, " to ")
					if len(parts) > 1 {
						fixedVersion = strings.TrimSpace(parts[1])
					}
				}
			}

			manifest.Updates = append(manifest.Updates, UpdatePackage{
				Name:             mappedPkg,
				InstalledVersion: installedVersion,
				FixedVersion:     fixedVersion,
				VulnerabilityID:  vuln.CVE,
			})
			processedPackages[pkgName] = true
		}
	}

	if len(manifest.Updates) == 0 {
		log.Printf("No packages to update")
		return "", nil
	}

	// Convert manifest to JSON
	output, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal manifest: %v", err)
	}

	return string(output), nil
}

func mapToDebianPackage(pkgName string) string {
	if mappedName, ok := packageMappings[pkgName]; ok {
		log.Printf("Found mapping for %s: %s", pkgName, mappedName)
		return mappedName
	}
	log.Printf("Using package name as is: %s", pkgName)
	return pkgName
}
