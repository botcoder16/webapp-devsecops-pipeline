def generate_wafw00f_command(options):
    # Initialize WAFW00F command
    wafw00f_command = ["wafw00f"]

    # Add target URL
    wafw00f_command.append(options["target_url"])

    # Output file (JSON format)
    if "output_format" in options and options["output_format"] == "json":
        wafw00f_command.extend(["-f", "json"])
        
    # Verbosity
    if "verbose" in options and options["verbose"]:
        wafw00f_command.append("-v")
    
    wafw00f_command.append("-a")
    wafw00f_command.append("-r")
        
    wafw00f_command.extend(["-o", "scan_results/wafw00f_scan.json"])
    # Return the generated command as a string
    return " ".join(wafw00f_command)
