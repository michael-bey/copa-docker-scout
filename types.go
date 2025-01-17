// Type definitions for fake scanner report
package main

// DockerScoutReport represents the structure of a Docker Scout vulnerability report
type DockerScoutReport struct {
	Vulnerabilities []struct {
		CVE         string `json:"cve"`
		Description string `json:"description"`
		Solution    string `json:"solution"`
		Location    struct {
			OperatingSystem string `json:"operating_system"`
			Dependency      struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"dependency"`
		} `json:"location"`
	} `json:"vulnerabilities"`
}

// UpdateManifest represents the structured output for Copa
type UpdateManifest struct {
	APIVersion string         `json:"apiVersion"`
	Metadata   Metadata       `json:"metadata"`
	Updates    UpdatePackages `json:"updates"`
}

// UpdatePackages is a list of UpdatePackage
type UpdatePackages []UpdatePackage

// Metadata contains information about the OS and config
type Metadata struct {
	OS     OS     `json:"os"`
	Config Config `json:"config"`
}

// OS contains information about the operating system
type OS struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

// Config contains information about the architecture
type Config struct {
	Arch string `json:"arch"`
}

// UpdatePackage contains information about the package update
type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}
