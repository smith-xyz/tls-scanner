package output

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/openshift/tls-scanner/internal/scanner"
)

func WriteJSONOutput(data interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	log.Printf("JSON output written to: %s", filename)
	return nil
}

func WriteOutputFiles(results scanner.ScanResults, artifactDir, jsonFile, csvFile, junitFile string, pqcCheck bool) error {
	if jsonFile == "" && csvFile == "" && junitFile == "" {
		return nil
	}

	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("could not create artifact directory %s: %v", artifactDir, err)
	}
	log.Printf("Artifacts will be saved to: %s", artifactDir)

	if jsonFile != "" {
		jsonPath := jsonFile
		if !filepath.IsAbs(jsonPath) {
			jsonPath = filepath.Join(artifactDir, jsonFile)
		}
		if err := WriteJSONOutput(results, jsonPath); err != nil {
			log.Printf("Error writing JSON output: %v", err)
		} else {
			log.Printf("JSON results written to: %s", jsonPath)
		}
	}

	if csvFile != "" {
		csvPath := csvFile
		if !filepath.IsAbs(csvPath) {
			csvPath = filepath.Join(artifactDir, csvFile)
		}
		if err := WriteCSVOutput(results, csvPath); err != nil {
			log.Printf("Error writing CSV output: %v", err)
		} else {
			log.Printf("CSV results written to: %s", csvPath)
		}

		if len(results.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + "_errors.csv"
			if err := WriteScanErrorsCSV(results, errorFilename); err != nil {
				log.Printf("Error writing scan errors CSV: %v", err)
			} else {
				log.Printf("Scan errors written to: %s", errorFilename)
			}
		}
	}

	if junitFile != "" {
		junitPath := junitFile
		if !filepath.IsAbs(junitPath) {
			junitPath = filepath.Join(artifactDir, junitFile)
		}
		if err := WriteJUnitOutput(results, junitPath, pqcCheck); err != nil {
			log.Printf("Error writing JUnit XML output: %v", err)
		} else {
			log.Printf("JUnit XML results written to: %s", junitPath)
		}
	}

	return nil
}
