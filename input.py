# Helper functions
def get_yes_no(prompt):
    while True:
        choice = input(prompt + " (y/n): ").lower()
        if choice in ['y', 'n']:
            return choice == 'y'
        print("Invalid input. Enter 'y' or 'n'.")

def get_input(prompt, default=""):
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default

# Main function to collect scan options
def collect_scan_options():
    # Initialize options dictionary
    options = {
        "output_format": "json"  # Compulsory JSON output for both tools
    }

    # Target URL (common for both tools)
    options["target_url"] = input("Enter target URL (required): ").strip()
    if not options["target_url"]:
        print("Error: Target URL is required.")
        exit(1)

    # Verbosity (common for both tools)
    if get_yes_no("Enable verbose mode?"):
        options["verbose"] = True

    # Scope control for Wapiti
    if get_yes_no("Configure crawl scope?"):
        options["crawl_scope"] = get_input("Crawl scope (page/folder/domain/punk)", "folder")
        if get_yes_no("Include external domains?"):
            options["external_domains"] = input("Comma-separated domains (e.g., google.com): ")
        if get_yes_no("Exclude URLs?"):
            options["exclude_urls"] = input("Regex for URLs to exclude: ")

    # Authentication for Wapiti
    if get_yes_no("Use authentication ?"):
        options["auth_method"] = get_input("Auth method (basic/digest/ntlm/post)", "basic")
        options["auth_credentials"] = input("Credentials (user:password): ")
        if get_yes_no("Use login form?"):
            options["login_form_url"] = input("Login form URL: ")
            options["login_form_data"] = input("Form data (e.g., user=admin&pass=admin): ")
        if get_yes_no("Add custom cookies?"):
            options["custom_cookie"] = input("Enter the cookie [name=value]: ")


    # Scan configuration for Wapiti
    options["max_depth"] = get_input("Max crawl depth", "40")
    options["max_links"] = get_input("Max links to crawl", "1000")
    
    # Rate limiting (common for both tools)
    if get_yes_no("Enable rate limiting?"):
        options["rate_limit"] = input("Enter the rate limit (requests per second): ")
        options["delay"] = input("Enter the delay between requests (in seconds)(for some tools): ")
    if get_yes_no("Set max scan time?"):
        options["max_attack_time"] = input("Max time in seconds: ")
    if get_yes_no("Set concurrency Threads?"):
        options["thread_concurrency"] = input("Enter the number of concurrent threads: ")
    if get_yes_no("Set timeout for requests?"):
        options["timeout"] = get_input("Timeout in seconds", "30")
        
    # Request options for Wapiti
    if get_yes_no("Add custom headers?"):
        options["custom_headers"] = input("Headers (e.g., 'Cookie: abc=123'): ")
    if get_yes_no("Set Custome User-Agent?"):    
        options["user_agent"] = get_input("User-Agent: ", "Mozilla/5.0")
    if get_yes_no("Send POST data ?"):
        options["wapiti_post_data"] = input("POST data (e.g., 'param=value'): ")


    # Miscellaneous for Wapiti
    if get_yes_no("Disable SSL verification ?"):
        options["wapiti_disable_ssl_verify"] = True
    
    # Modules for Wapiti
    modules = {
        1: "sql", 2: "xss", 3: "exec", 4: "file", 5: "cors",
        6: "htaccess", 7: "backup", 8: "crlf", 9: "ssrf", 10: "csrf"
    }
    print("\nAvailable modules for Wapiti:")
    for num, mod in modules.items():
        print(f"{num}: {mod}")
    selected = input("Enter module numbers (comma-separated, e.g., 1,2): ")
    if selected:
        options["wapiti_modules"] = [modules[int(num)] for num in selected.split(",")]
    
    options["wapiti_force"] = input("Scan force for wapiti [paranoid, sneaky, polite, normal, aggressive, insane] :")
    
    # Template selection for Nuclei
    print("\n1. Use all templates for Nuclei")
    print("2. Use specific templates (e.g., cves, misconfigurations)")
    print("3. Exclude specific templates")
    template_method = input("Choose template selection method for Nuclei (1, 2, or 3): ")

    while template_method not in ["1", "2", "3"]:
        print("Invalid choice. Please select 1, 2, or 3.")
        template_method = input("Choose template selection method for Nuclei (1, 2, or 3): ")
        if template_method == "1":
            options["nuclei_templates"] = "all"
        elif template_method == "2":
            options["nuclei_templates"] = input("Enter the path to the templates (e.g., templates/cves/): ")
        elif template_method == "3":
            options["nuclei_exclude_templates"] = input("Enter the path to exclude templates (e.g., templates/misc/): ")
        
    print("\n1. Critical")
    print("2. High")
    print("3. Medium")
    print("4. Low")
    print("5. Info")

    severity_mapping = {
        "1": "critical",
        "2": "high",
        "3": "medium",
        "4": "low",
        "5": "info",
    }

    while True:
        severity_input = input("Choose severity level(s) for Nuclei (comma-separated, e.g., 1,2 or 6 for all): ")
        selected = [s.strip() for s in severity_input.split(",")]

        # Validate all inputs are valid keys
        if all(s in severity_mapping for s in selected):
            nuclei_severity = [severity_mapping[s] for s in selected]
            break

        print("Invalid input. Please enter numbers between 1 and 6, separated by commas.")

    options["nuclei_severity"] = nuclei_severity
    # Return the options dictionary
    return options