def generate_nikto_command(options):
    # Initialize Nikto command
    nikto_command = ["nikto"]

    # Add target URL
    nikto_command.extend(["-h", options["target_url"]])

    # Output file (JSON format)
    if "output_format" in options and options["output_format"] == "json":
        nikto_command.extend(["-Format", "xml"])
        nikto_command.extend(["-o", "~/scan_results/nikto_scan.xml"])
    # Verbosity
    if "verbose" in options and options["verbose"]:
        nikto_command.append("-v")

    if "max_attack_time" in options:
        nikto_command.extend(["-until", options["max_attack_time"]])

    nikto_command.extend(["-Tuning", "x"])
    
    if "auth_credentials" in options:
        nikto_command.extend(["-id", options["auth_credentials"]])

    if "wapiti_disable_ssl_verify" in options:
        nikto_command.append("-nossl")
    else:
        nikto_command.append("-ssl")
    # Return the generated command as a string
    return " ".join(nikto_command)
