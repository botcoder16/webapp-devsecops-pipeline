def generate_nuclei_command(options):
    # Initialize Nuclei command
    nuclei_command = ["echo", options["target_url"], "|", "/home/tool_backend/go/bin/hakrawler", "-d", options["max_depth"], "|", "grep", "="]
    nuclei_command.extend(["|","nuclei"])

    # Output file (JSON format)
    if options.get("output_format") == "json":
        nuclei_command.extend(["-j", "-o", "~/scan_results/nuclei_scan.json"])

    # Template selection
    
    if options["nuclei_template_method"] == "specific":
        nuclei_command.extend(["-t", options["nuclei_templates"]])
    elif options.get("nuclei_template_method") == "exclude":
        nuclei_command.extend(["-exclude", options["nuclei_exclude_templates"]])
    elif options.get("nuclei_template_method") == "dast":
        nuclei_command.extend(["-t", "~/nuclei-templates/dast/vulnerabilities/ -dast -headless"])  
    
    if options.get("nuclei_severity"):
        severity_str = ",".join(options["nuclei_severity"])
        nuclei_command.extend(["-s", severity_str])

            
    

    # Mapping of Nuclei options to command-line flags
    option_mappings = {
        "rate_limit": "-rate-limit",
        "thread_concurrency": "-c"
    }

    # Add options to the command
    for key, flag in option_mappings.items():
        if options.get(key):
            nuclei_command.extend([flag, options[key]])

    # Handle boolean flags separately
    if options.get("verbose"):
        nuclei_command.append("-v")

    # Return the generated command as a string
    return " ".join(nuclei_command)
#echo http://testphp.vulnweb.com | hakrawler -d 2 | grep = | nuclei -t ~/nuclei-templates/dast/vulnerabilities/ -dast -headless -s critical,high