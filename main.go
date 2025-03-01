package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// ToolList holds the names of tools required for enumeration
var tools = []string{
	"subfinder",
	"amass",
	"assetfinder",
	"sublist3r",
	"jq",
	"httpx",
	"ffuf",
}

// Ensure OUTPUT directory exists
func createOutputDir() {
	if _, err := os.Stat("OUTPUT"); os.IsNotExist(err) {
		err := os.Mkdir("OUTPUT", 0755)
		if err != nil {
			log.Fatal("Failed to create OUTPUT directory:", err)
		}
	}
}

// InstallTool checks if the tool is installed, and installs it if missing
func installTool(tool string) {
	_, err := exec.LookPath(tool)
	if err != nil {
		fmt.Printf("%s not found! Installing...\n", tool)
		switch tool {
		case "subfinder":
			installSubfinder()
		case "amass":
			installAmass()
		case "assetfinder":
			installAssetfinder()
		case "sublist3r":
			installSublist3r()
		case "jq":
			installJq()
		case "httpx":
			installHttpx()
		case "ffuf":
			installFfuf()
		}
	} else {
		fmt.Printf("%s is already installed.\n", tool)
	}
}

func installSubfinder() {
	runCommand("go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
}

func installAmass() {
	runCommand("go", "install", "github.com/owasp-amass/amass/v4/...@master")
}

func installAssetfinder() {
	runCommand("go", "install", "github.com/tomnomnom/assetfinder@latest")
}

func installSublist3r() {
	runCommand("pip3", "install", "sublist3r")
}

func installJq() {
	runCommand("sudo", "apt", "install", "-y", "jq")
}

func installFfuf() {
	runCommand("go", "install", "github.com/ffuf/ffuf/v2@latest")
}

func installHttpx() {
	runCommand("go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
}

// RunCommand executes a command and handles errors
func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to execute %s: %v\n", name, err)
	}
}

// RunSubdomainEnum executes all enumeration tools
func runSubdomainEnum(domain string) {
	fmt.Printf("\033[1;36mStarting Subdomain Enumeration for %s...\033[0m\n", domain)

	createOutputDir()

	runTool("subfinder", "-d", domain, "-all", "-o", "OUTPUT/subfinder_output.txt")
	runTool("amass", "enum", "-active", "-brute", "-d", domain, "-o", "OUTPUT/amass_output.txt")
	runCommand("bash", "-c", fmt.Sprintf("assetfinder --subs-only %s > OUTPUT/assetfinder_output.txt", domain))

	// Fetch subdomains from certificate transparency logs
	runCurl(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain), "OUTPUT/crt_output.txt")
	runCommand("bash", "-c", "jq -r '.[].name_value' OUTPUT/crt_output.txt | sed 's/\\*\\.//g' | sort -u > OUTPUT/crt_subs.txt")

	runCurl(fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain), "OUTPUT/certspotter_output.txt")
	runCommand("bash", "-c", "jq -r '.[].dns_names[]' OUTPUT/certspotter_output.txt | sed 's/\\*\\.//g' | sort -u > OUTPUT/certspotter_subs.txt")

	// Brute-force subdomains using ffuf
	runTool("ffuf", "-w", "/Users/narayanan/Documents/ionic/IonicSub/resource/subdomains-top2million-281163.txt", "-u", fmt.Sprintf("https://FUZZ.%s", domain), "-o", "OUTPUT/ffuf_output.txt")

	// Combine all subdomains
	runCommand("bash", "-c", "cat OUTPUT/*.txt | sort -u > OUTPUT/all_subdomains.txt")

	// Check for live subdomains using httpx
	runCommand("bash", "-c", "cat OUTPUT/all_subdomains.txt | httpx -silent -threads 100 -o OUTPUT/live_subdomains.txt")
}

// runTool executes a tool with arguments
func runTool(tool string, args ...string) {
	cmd := exec.Command(tool, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to run %s: %v", tool, err)
	}
}

// runCurl fetches data from a URL and saves it to a file
func runCurl(url, outputFile string) {
	cmd := exec.Command("curl", "-s", url)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to fetch data from %s: %v", url, err)
		return
	}
	if err := os.WriteFile(outputFile, out, 0644); err != nil {
		log.Printf("Failed to write to %s: %v", outputFile, err)
	}
}

// Display banner
func displayBanner() {
	fmt.Println("\033[1;34m")
	fmt.Println("  ██╗ ██████╗ ███╗   ██╗██╗ ██████╗███████╗██╗   ██╗██████╗ ")
	fmt.Println("  ██║██╔═══██╗████╗  ██║██║██╔════╝██╔════╝██║   ██║██╔══██╗")
	fmt.Println("  ██║██║   ██║██╔██╗ ██║██║██║     ███████╗██║   ██║██████╔╝")
	fmt.Println("  ██║██║   ██║██║╚██╗██║██║██║     ╚════██║██║   ██║██╔══██╗")
	fmt.Println("  ██║╚██████╔╝██║ ╚████║██║╚██████╗███████║╚██████╔╝██████╔╝")
	fmt.Println("  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═════╝ ")
	fmt.Println("\033[0m")
	fmt.Println("\033[1;36mSubdomain Enumeration Script\033[0m")
}

// Main function
func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		displayBanner()
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Println("\033[1;31mError: Domain not provided!\033[0m")
		displayBanner()
		os.Exit(1)
	}

	domain := os.Args[1]

	displayBanner()

	for _, tool := range tools {
		installTool(tool)
	}

	runSubdomainEnum(domain)

	fmt.Println("\033[1;32mSubdomain Enumeration Completed!\033[0m")
	fmt.Println("\033[1;32mResults saved in OUTPUT/live_subdomains.txt\033[0m")
}
