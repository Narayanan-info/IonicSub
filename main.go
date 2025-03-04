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
	"assetfinder",
	"jq",
	"httpx",
	"fuff",
}

// Ensure OUTPUT and HTTPX directories exist
func createOutputDirs() {
	dirs := []string{"OUTPUT", "OUTPUT/httpx"}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.Mkdir(dir, 0755)
			if err != nil {
				log.Fatal("Failed to create ", dir, " directory:", err)
			}
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
		case "assetfinder":
			installAssetfinder()
		case "jq":
			installJq()
		case "httpx":
			installHttpx()
		case "fuff":
			installFuff()
		}
	} else {
		fmt.Printf("%s is already installed.\n", tool)
	}
}

func installSubfinder() {
	runCommand("go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
}

func installAssetfinder() {
	runCommand("go", "install", "github.com/tomnomnom/assetfinder@latest")
}

func installJq() {
	runCommand("sudo", "apt", "install", "-y", "jq")
}

func installHttpx() {
	runCommand("go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
}

func installFuff() {
	runCommand("go", "install", "github.com/ffuf/ffuf/v2@latest")
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

	createOutputDirs()

	runTool("subfinder", "-d", domain, "-all", "-o", "OUTPUT/subfinder_output.txt")
	runCommand("bash", "-c", fmt.Sprintf("assetfinder --subs-only %s > OUTPUT/assetfinder_output.txt", domain))
	runTool("ffuf", "-u", "https://FUZZ."+domain, "-w", "/Users/narayanan/Documents/ionic/IonicSub/resource/all-bug-bounty.txt", "-mc", "200", "-o", "OUTPUT/fuff_output.txt")

	// Fetch subdomains from certificate transparency logs
	runCurl(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain), "OUTPUT/crt_output.txt")
	runCommand("bash", "-c", "jq -r '.[].name_value' OUTPUT/crt_output.txt | sed 's/\\*\\.//g' | sort -u > OUTPUT/crt_subs.txt")

	runCurl(fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain), "OUTPUT/certspotter_output.txt")
	runCommand("bash", "-c", "jq -r '.[].dns_names[]' OUTPUT/certspotter_output.txt | sed 's/\\*\\.//g' | sort -u > OUTPUT/certspotter_subs.txt")

	// Combine all subdomains
	runCommand("bash", "-c", "cat OUTPUT/subfinder_output.txt assetfinder_output.txt crt_subs.txt certspotter_subs.txt fuff_output.txt | sort -u > OUTPUT/all_subdomains.txt")

	// Run httpx with status filtering
	runCommand("bash", "-c", "cat OUTPUT/all_subdomains.txt | httpx -silent -mc 200,403,401,302,304,404,500,301 -o OUTPUT/httpx/all_status.txt")

	runCommand("bash", "-c", "cat OUTPUT/httpx/all_status.txt | httpx -status-code -o OUTPUT/httpx/all-status-code.txt")

	runCommand("bash", "-c", "grep 200 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/200_domains.txt")
	runCommand("bash", "-c", "grep 403 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/403_domains.txt")
	runCommand("bash", "-c", "grep 401 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/401_domains.txt")
	runCommand("bash", "-c", "grep 302 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/302_domains.txt")
	runCommand("bash", "-c", "grep 304 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/304_domains.txt")
	runCommand("bash", "-c", "grep 301 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/301_domains.txt")
	runCommand("bash", "-c", "grep 404 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/404_domains.txt")
	runCommand("bash", "-c", "grep 500 OUTPUT/httpx/all-status-code.txt | awk '{print $1}' > OUTPUT/httpx/500_domains.txt")

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
	fmt.Println("██╗ ██████╗ ███╗   ██╗██╗ ██████╗███████╗██╗   ██╗██████╗ ")
	fmt.Println("██║██╔═══██╗████╗  ██║██║██╔════╝██╔════╝██║   ██║██╔══██╗")
	fmt.Println("██║██║   ██║██╔██╗ ██║██║██║     ███████╗██║   ██║██████╔╝")
	fmt.Println("██║██║   ██║██║╚██╗██║██║██║     ╚════██║██║   ██║██╔══██╗")
	fmt.Println("██║╚██████╔╝██║ ╚████║██║╚██████╗███████║╚██████╔╝██████╔╝")
	fmt.Println("╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═════╝ ")
	fmt.Println("\033[0m")
	fmt.Println("\033[1;36mSubdomain Enumeration Script\033[0m")
	fmt.Println("\033[1;36mUsage: ./ionicsub <domain>\033[0m")
	fmt.Println("\033[1;36mExample: ./ionicsub example.com\033[0m")
	fmt.Println("\033[1;36m----------------------------------------\033[0m")
	fmt.Println("\033[1;36mOptions:\033[0m")
	fmt.Println("\033[1;36m  -h, --help    Show this help message and exit\033[0m")
	fmt.Println("\033[1;36m----------------------------------------\033[0m")
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
