def generate_whatweb_command(options):
    # Initialize WhatWeb command
    whatweb_command = ["whatweb"]

    # Add target URL
    whatweb_command.append(options["target_url"])

    # Output file (JSON format)
    if "output_format" in options and options["output_format"] == "json":
        whatweb_command.append("--log-json-verbose=scan_results/whatweb_scan.json")
        
    if "verbose" in options:
        whatweb_command.append("-v")
    
    whatweb_command.append("-a")
    whatweb_command.append("3")
    #Max Threads
    if "thread_concurrency" in options:
        whatweb_command.extend(["-t", options["thread_concurrency"]])
        
    if "custom_cookie" in options:
        whatweb_command.append(f"--cookie={options['custom_cookie']}")

    # Return the generated command as a string
    return " ".join(whatweb_command)
