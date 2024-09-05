package jsonutils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"ImageWebhookScaner/models"
)

func GenerateJSONResponce(trivySummary *models.TrivyScanSummary) []byte {
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
func ReadJSONFile(fileName string) (*models.ImageReview, error) {
	jsonData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fileName, err)
	}
	fmt.Printf("Successfully Opened %s\n", fileName)

	var outputJSON models.ImageReview

	err = json.Unmarshal(jsonData, &outputJSON)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON data: %v", err)
	}

	return &outputJSON, nil
}
