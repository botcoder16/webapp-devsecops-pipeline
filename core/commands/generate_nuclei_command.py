def generate_nuclei_command(options):
    # Initialize Nuclei command
    nuclei_command = ["nuclei", "-u", options["target_url"]]

    # Output file (JSON format)
    if options.get("output_format") == "json":
        nuclei_command.extend(["-je", "-o", "~/scan_results/nuclei_scan.json"])

    # Template selection
    if options.get("nuclei_templates"):
        if options["nuclei_templates"] != "all":
            nuclei_command.extend(["-t", options["nuclei_templates"]])
    
    if options.get("nuclei_severity"):
        severity_str = ",".join(options["nuclei_severity"])
        nuclei_command.extend(["-severity", severity_str])

            
    if options.get("nuclei_exclude_templates"):
        nuclei_command.extend(["-exclude", options["nuclei_exclude_templates"]])

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