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
	"findomain",
	"amass",
	"assetfinder",
	"sublist3r",
	"jq",
	"massdns",
	"altdns",
	"httpx",
}

// InstallTool checks if the tool is installed, and installs it if missing
func installTool(tool string) {
	_, err := exec.LookPath(tool)
	if err != nil {
		fmt.Printf("%s not found! Installing...\n", tool)
		switch tool {
		case "subfinder":
			installSubfinder()
		case "findomain":
			installFindomain()
		case "amass":
			installAmass()
		case "assetfinder":
			installAssetfinder()
		case "sublist3r":
			installSublist3r()
		case "jq":
			installJq()
		case "massdns":
			installMassdns()
		case "altdns":
			installAltdns()
		case "httpx":
			installHttpx()
		}
	} else {
		fmt.Printf("%s is already installed.\n", tool)
	}
}

func installSubfinder() {
	cmd := exec.Command("go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install subfinder:", err)
	}
}

func installFindomain() {
	cmd := exec.Command("sudo", "apt", "install", "findomain")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install findomain:", err)
	}
}

func installAmass() {
	cmd := exec.Command("go", "install", "github.com/owasp-amass/amass/v4/...@master")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install amass:", err)
	}
}

func installAssetfinder() {
	cmd := exec.Command("go", "install", "github.com/tomnomnom/assetfinder@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install assetfinder:", err)
	}
}

func installSublist3r() {
	cmd := exec.Command("sudo", "apt", "install", "sublist3r")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install Sublist3r:", err)
	}
}

func installJq() {
	cmd := exec.Command("sudo", "apt", "install", "-y", "jq")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install jq:", err)
	}
}

func installMassdns() {
	cmd := exec.Command("sudo", "apt", "install", "massdns")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install massdns:", err)
	}
}

func installAltdns() {
	cmd := exec.Command("sudo", "apt", "install", "altdns")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install altdns:", err)
	}
}

func installHttpx() {
	cmd := exec.Command("go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to install httpx:", err)
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
	fmt.Println("\033[1;36mUsage: ./subdomain_enum.sh <domain>\033[0m")
	fmt.Println("\033[1;36mExample: ./subdomain_enum.sh example.com\033[0m")
	fmt.Println("\033[1;36m----------------------------------------\033[0m")
	fmt.Println("\033[1;36mOptions:\033[0m")
	fmt.Println("\033[1;36m  -h, --help    Show this help message and exit\033[0m")
	fmt.Println("\033[1;36m----------------------------------------\033[0m")
}

// RunSubdomainEnum runs all the tools for subdomain enumeration
func runSubdomainEnum(domain string) {
	fmt.Printf("\033[1;36mStarting Subdomain Enumeration for %s...\033[0m\n", domain)

	// Run all tools (example for one tool, replicate for all)
	// Run subdomain enumeration tools
	runTool("subfinder", "-d", domain, "-all", "-o", "subfinder.txt")
	runTool("findomain", "-t", domain, "-u", "findomain.txt")
	runTool("amass", "enum", "-active", "-brute", "-d", domain, "-o", "amass.txt")
	runTool("assetfinder", "--subs-only", domain, ">", "assetfinder.txt")
	runTool("sublist3r", "-d", domain, "-o", "sublist3r.txt")

	// Fetch subdomains from certificate transparency logs
	runCurl("https://crt.sh/?q=%25."+domain+"&output=json", "crt.txt")
	runCurl("https://api.certspotter.com/v1/issuances?domain="+domain+"&include_subdomains=true&expand=dns_names", "certspotter.txt")

	// Brute-force subdomains using massdns
	runTool("sh", "-c", "cat /Users/narayanan/Documents/ionic/IonicSub/resource/subdomains-top2million-281163.txt | sed 's/$/."+domain+"/' | massdns -r /Users/narayanan/Documents/ionic/IonicSub/resource/resolvers.txt -t A -o S -w massdns_output.txt")
	runTool("sh", "-c", "cat massdns_output.txt | awk '{print $1}' | sed 's/.$//' | sort -u > brute_forced_subdomains.txt")

	// Combine all subdomains into one file
	runTool("sh", "-c", "cat amass.txt subfinder.txt assetfinder.txt findomain.txt sublist3r.txt crt.txt certspotter.txt brute_forced_subdomains.txt | sort -u > all_subdomains.txt")

	// Generate permutations using altdns
	runTool("altdns", "-i", "all_subdomains.txt", "-o", "permutations.txt", "-w", "/Users/narayanan/Documents/ionic/IonicSub/resource/subdomains-top2million-281163.txt")
	runTool("sh", "-c", "cat permutations.txt | massdns -r /Users/narayanan/Documents/ionic/IonicSub/resource/resolvers.txt -t A -o S -w permuted_subdomains.txt")
	runTool("sh", "-c", "cat permuted_subdomains.txt | awk '{print $1}' | sed 's/.$//' | sort -u >> all_subdomains.txt")

	// Check for live subdomains using httpx
	runTool("sh", "-c", "cat all_subdomains.txt | httpx -silent -threads 100 -o live_subdomains.txt")

}

// runTool executes a tool with arguments
func runTool(tool string, args ...string) {
	cmd := exec.Command(tool, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to run %s: %v", tool, err)
	}
}

// runCurl runs a curl command
func runCurl(url, outputFile string) {
	cmd := exec.Command("curl", "-s", url)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to fetch data from %s: %v", url, err)
		return
	}
	file, err := os.Create(outputFile)
	if err != nil {
		log.Printf("Failed to create file %s: %v", outputFile, err)
		return
	}
	defer file.Close()
	_, err = file.Write(out)
	if err != nil {
		log.Printf("Failed to write to %s: %v", outputFile, err)
	}
}

func main() {

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		displayBanner() // Display the banner
		os.Exit(0)      // Exit after displaying the banner
	}

	if len(os.Args) < 2 {
		fmt.Println("\033[1;31mError: Domain not provided!\033[0m")
		displayBanner()
		os.Exit(1)
	}

	domain := os.Args[1]

	// Display banner and install tools
	displayBanner()

	// Check and install tools
	for _, tool := range tools {
		installTool(tool)
	}

	// Run Subdomain Enumeration
	runSubdomainEnum(domain)

	fmt.Println("\033[1;32mSubdomain Enumeration Completed!\033[0m")
	fmt.Println("\033[1;32mResults saved in live_subdomains.txt\033[0m")
}
