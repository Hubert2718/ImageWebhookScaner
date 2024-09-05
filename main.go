package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

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

func main() {
	//Check if a file name is provisioned as command-line argument
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <input_file.json>", os.Args[0])
	}

	// read the JSON file specified as the first argument
	fileName := os.Args[1]

	// this holds an addres (pointer -> *) of unmarshalled json ImageReview struct
	outputJSON, err := readJSONFile(fileName)
	if err != nil {
		log.Fatalf("Failed to read and unmarshal JSON file: %s", err)
	}

	fmt.Printf("Unmarshalled JSON Struct: %+v\n", *outputJSON)

	// Initialize the scan summary for images with critical vulnerabilities
	trivySummary := &TrivyScanSummary{
		Images: make(map[string][]ScanResult),
	}

	// Iterate over the images in the JSON and run trivy against each
	for _, container := range outputJSON.Spec.Containers {
		fmt.Printf("\nRunning Trivy scan for image: %s\n", container.Image)
		scanResult, err := runTrivyScan(container.Image)
		if err != nil {
			log.Printf("Error scanning image %s: %v", container.Image, err)
			continue
		}

		// Store the scan result only if there are critical vulnerabilities
		if len(scanResult.Vulnerabilities) > 0 {
			trivySummary.Images[container.Image] = append(trivySummary.Images[container.Image], scanResult)
		}
	}

	responseJSON := generateJSONResponce(trivySummary)
	fmt.Print(string(responseJSON))
}

func generateJSONResponce(trivySummary *TrivyScanSummary) []byte {
	var responseJSON []byte
	if len(trivySummary.Images) > 0 {
		// If there are any vulnerabilities
		reasons := []string{}
		for image := range trivySummary.Images {
			reasons = append(reasons, fmt.Sprintf("image %s has vulnerabilities", image))
		}
		reason := strings.Join(reasons, ", ")

		response := map[string]interface{}{
			"apiVersion": "imagepolicy.k8s.io/v1alpha1",
			"kind":       "ImageReview",
			"status": map[string]interface{}{
				"allowed": false,
				"reason":  reason,
			},
		}

		// Convert to JSON and print
		responseJSON, _ = json.MarshalIndent(response, "", "  ")
	} else {
		// If no vulnerabilities are found
		response := map[string]interface{}{
			"apiVersion": "imagepolicy.k8s.io/v1alpha1",
			"kind":       "ImageReview",
			"status": map[string]interface{}{
				"allowed": true,
			},
		}

		// Convert to JSON and print
		responseJSON, _ = json.MarshalIndent(response, "", "  ")
	}
	return responseJSON
}

/*
When you use os.ReadFile in Go, it reads the entire content of a file and returns it as a []byte.
A []byte in Go is a slice, and slices in Go are a reference type.
This means that when you return a []byte from a function, you're actually returning a slice header, not a deep copy of the entire underlying array.
*/
func readJSONFile(fileName string) (*ImageReview, error) {
	jsonData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fileName, err)
	}
	fmt.Printf("Successfully Opened %s\n", fileName)

	var outputJSON ImageReview

	err = json.Unmarshal(jsonData, &outputJSON)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON data: %v", err)
	}

	return &outputJSON, nil
}

func runTrivyScan(image string) (ScanResult, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", image)

	// Run the command and print its output in real-time
	output, err := cmd.Output()
	if err != nil {
		return ScanResult{}, fmt.Errorf("error running trivy for image %s: %v", image, err)
	}

	var trivyResult TrivyOutput
	err = json.Unmarshal(output, &trivyResult)
	if err != nil {
		return ScanResult{}, fmt.Errorf("error unmarshalling trivy output for image %s: %v", image, err)
	}

	// Initialize a ScanResult to collect critical vulnerabilities
	scanResults := ScanResult{
		Target:          trivyResult.ArtifactName,
		Vulnerabilities: []Vulnerability{},
	}

	for _, result := range trivyResult.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == "CRITICAL" {
				scanResults.Vulnerabilities = append(scanResults.Vulnerabilities, vuln)
			}
		}
	}

	// Only return results if there are critical vulnerabilities
	if len(scanResults.Vulnerabilities) > 0 {
		return scanResults, nil
	}

	fmt.Println("No critical vulnerabilities found for image:", image)
	return ScanResult{}, nil
}
