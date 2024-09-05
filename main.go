package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"

	"ImageWebhookScaner/jsonutils"
	"ImageWebhookScaner/models"
)

func main() {
	// Set up HTTP server
	http.HandleFunc("/", handleScanRequest)
	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServeTLS(":8080", "/etc/webhook/certs/cert.pem", "/etc/webhook/certs/key.pem", nil))
}

func handleScanRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read JSON data from the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	// ensures that r.Body.Close() is called when the function handleScanRequest finishes execution, regardless of whether it exits normally or because of an error.
	defer r.Body.Close()

	var outputJSON models.ImageReview
	err = json.Unmarshal(body, &outputJSON)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to unmarshal JSON: %s", err), http.StatusBadRequest)
		return
	}

	// Initialize the scan summary for images with critical vulnerabilities
	trivySummary := &models.TrivyScanSummary{
		Images: make(map[string][]models.ScanResult),
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

	responseJSON := jsonutils.GenerateJSONResponce(trivySummary)

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	w.Write(responseJSON)
}

func runTrivyScan(image string) (models.ScanResult, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", image)

	// Run the command and print its output in real-time
	output, err := cmd.Output()
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("error running trivy for image %s: %v", image, err)
	}

	var trivyResult models.TrivyOutput
	err = json.Unmarshal(output, &trivyResult)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("error unmarshalling trivy output for image %s: %v", image, err)
	}

	// Initialize a ScanResult to collect critical vulnerabilities
	scanResults := models.ScanResult{
		Target:          trivyResult.ArtifactName,
		Vulnerabilities: []models.Vulnerability{},
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
	return models.ScanResult{}, nil
}
