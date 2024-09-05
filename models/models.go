package models

type ImageReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       Spec   `json:"spec"`
}

type Spec struct {
	Containers  []Container       `json:"containers"`
	Annotations map[string]string `json:"annotations"`
	Namespace   string            `json:"namespace"`
}

type Container struct {
	Image string `json:"image"`
}

type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
}

type ScanResult struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// Struct to store aggregated scan summaries for all images
type TrivyScanSummary struct {
	Images map[string][]ScanResult `json:"images"`
}

// Trivy output structure to parse JSON results
type TrivyOutput struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	Results       []Result `json:"Results"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}
