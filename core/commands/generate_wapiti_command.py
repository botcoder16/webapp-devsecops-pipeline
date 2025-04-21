import json

def generate_wapiti_command(options):
    # Initialize Wapiti command
    wapiti_command = ["wapiti", "-u", options["target_url"]]

    # Output file (JSON format)
    if options.get("output_format") == "json":
        wapiti_command.extend(["-f", "json", "-o", "/home/tool_backend/scan_results/wapiti_scan.json"])

    # Mapping of Wapiti options to command-line flags
    option_mappings = {
        "crawl_scope": "--scope",
        "wapiti_external_domains": "--external",
        "exclude_urls": "--exclude",
        "auth_method": "--auth-method",
        "auth_credentials": "--auth-cred",
        "login_form_url": "--form-url",
        "login_form_data": "--form-data",
        "wapiti_cookie_file": "--cookie",
        "max_depth": "-d",
        "max_links": "--max-links",
        "max_attack_time": "--max-scan-time",
        "custom_headers": "--header",
        "user_agent": "--user-agent",
        "wapiti_post_data": "--data",
        "timeout": "--timeout",
        "wapiti_exclude_params": "-r",
        "wapiti_verbosity": "-v",
        "wapiti_disable_ssl_verify": "--verify-ssl",
        "wapiti_force" : "-S",
    }

    # Add options to the command
    for key, flag in option_mappings.items():
        if options.get(key):
            wapiti_command.extend([flag, options[key]])

    # Modules (if specified)
    if options.get("wapiti_modules") != "all":
        wapiti_command.extend(["-m", ",".join(options["wapiti_modules"])])

    # Miscellaneous flags
    if options.get("wapiti_color_output"):
        wapiti_command.append("--color")
    if options.get("wapiti_disable_ssl_verify"):
        wapiti_command.append("-k")

    # Return the generated command as a string
    return " ".join(wapiti_command)