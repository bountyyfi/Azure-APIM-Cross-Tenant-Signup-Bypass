#!/usr/bin/env python3
"""
Azure APIM Vulnerability Verification Script
Checks if an APIM instance is vulnerable to cross-tenant signup bypass

Author: Mihalis Haatainen, Bountyy Oy
Date: November 26, 2025
"""

import argparse
import requests
from colorama import Fore, Style, init
from typing import Tuple

init(autoreset=True)


class APIMVulnerabilityChecker:
    def __init__(self, url: str, verbose: bool = False, verify_ssl: bool = True):
        self.url = url.rstrip('/')
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def log_check(self, message: str):
        print(f"{Fore.BLUE}[?]{Style.RESET_ALL} {message}")

    def log_vuln(self, message: str):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")

    def log_safe(self, message: str):
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {message}")

    def log_info(self, message: str):
        print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} {message}")

    def check_signup_endpoint(self) -> Tuple[bool, str]:
        """Check if /signup endpoint is accessible."""
        self.log_check("Checking signup endpoint accessibility...")
        try:
            response = self.session.get(f'{self.url}/signup', timeout=10)
            if response.status_code in [200, 302]:
                return True, "Signup endpoint is accessible"
            else:
                return False, f"Signup endpoint returned {response.status_code}"
        except requests.exceptions.SSLError as e:
            return None, f"SSL_ERROR: {str(e)}"
        except Exception as e:
            return False, f"Error accessing signup endpoint: {str(e)}"

    def check_basic_auth(self) -> Tuple[bool, str]:
        """Check if Basic Authentication signup API is accessible (bypassing UI)."""
        self.log_check("Checking if Basic Auth signup API is accessible...")
        
        # Test payload - fake captcha will fail but endpoint will respond if active
        signup_payload = {
            "challenge": {
                "testCaptchaRequest": {
                    "challengeId": "00000000-0000-0000-0000-000000000000",
                    "inputSolution": "AAAAAA"
                },
                "azureRegion": "NorthCentralUS",
                "challengeType": "visual"
            },
            "signupData": {
                "email": "vuln-probe-test@nonexistent-invalid-domain.test",
                "firstName": "Probe",
                "lastName": "Test",
                "password": "VulnProbe123!",
                "confirmation": "signup",
                "appType": "developerPortal"
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Origin': self.url,
            'Referer': f'{self.url}/signup'
        }
        
        try:
            api_url = f'{self.url}/signup'
            if self.verbose:
                print(f"    Trying: POST {api_url}")
            
            response = self.session.post(
                api_url,
                json=signup_payload,
                timeout=10,
                headers=headers
            )
            
            if self.verbose:
                print(f"      -> {response.status_code}")
                print(f"      -> {response.text[:200]}...")
            
            response_text = response.text.lower()
            
            # 404 = endpoint doesn't exist
            if response.status_code == 404:
                # Check if it's HTML 404 page vs JSON 404
                if 'html' in response.text.lower() or '<!doctype' in response.text.lower():
                    return False, "Signup API not found (HTML 404)"
                return False, "Signup API not found (404)"
            
            # These responses indicate the signup API EXISTS and processes requests
            # Even captcha errors prove the endpoint is active
            if response.status_code == 400:
                if 'captcha' in response_text or 'challenge' in response_text:
                    return True, "Basic Auth signup API ACTIVE (captcha validation)"
                if 'email' in response_text or 'password' in response_text or 'invalid' in response_text:
                    return True, "Basic Auth signup API ACTIVE (input validation)"
                return True, f"Basic Auth signup API responds (400)"
            
            elif response.status_code == 409:
                return True, "Basic Auth signup API ACTIVE (409 conflict)"
            
            elif response.status_code == 200 or response.status_code == 201:
                return True, "Basic Auth signup API ACCEPTS requests"
            
            elif response.status_code == 401 or response.status_code == 403:
                return True, f"Basic Auth signup API responds ({response.status_code})"
            
            elif response.status_code == 422:
                return True, "Basic Auth signup API validates (422)"
            
            else:
                self.log_info(f"  /signup returned {response.status_code}")
                return None, f"Signup returned {response.status_code} - manual check recommended"
                
        except requests.exceptions.SSLError as e:
            return None, f"SSL_ERROR: {str(e)}"
        except requests.exceptions.Timeout:
            return None, "Connection timeout"
        except Exception as e:
            return None, f"Error: {str(e)}"

    def check_signup_disabled(self) -> Tuple[bool, str]:
        """Check if signup is disabled in UI (but API might still work = vulnerable)."""
        self.log_check("Checking if signup is hidden/disabled in UI...")
        try:
            response = self.session.get(f'{self.url}/signup', timeout=10)
            
            # If we get redirected away or 404, signup is hidden in UI
            if response.status_code == 404:
                return True, "Signup page returns 404 (hidden in UI)"
            elif response.status_code in [301, 302, 303, 307, 308]:
                return True, "Signup page redirects away (disabled in UI)"
            elif response.status_code == 200:
                # Page loads but might show "disabled" message
                # Note: Can't reliably check SPA content
                return False, "Signup page accessible (UI shows signup)"
            else:
                return None, f"Signup page returned {response.status_code}"
                
        except Exception as e:
            return None, f"Error checking signup page: {str(e)}"

    def check_vulnerability(self) -> dict:
        """
        Perform comprehensive vulnerability check.
        
        The vulnerability: Basic Auth signup API works even when UI hides/disables signup.
        This allows cross-tenant account creation by bypassing UI restrictions.
        
        Two scenarios:
        1. TARGET: Signup disabled in UI but API works = vulnerable to attack
        2. ATTACK SOURCE: Signup enabled = can be used to attack other instances
        
        Returns:
            Dictionary with check results
        """
        results = {
            'url': self.url,
            'vulnerable': False,
            'attack_source': False,
            'risk_level': 'Unknown',
            'checks': {}
        }
        
        # Check 1: Signup page accessible in UI
        signup_ui_accessible, signup_ui_msg = self.check_signup_endpoint()
        results['checks']['signup_ui'] = {
            'status': signup_ui_accessible,
            'message': signup_ui_msg
        }
        
        # Check for SSL error - can't determine vulnerability without connection
        if signup_ui_msg.startswith("SSL_ERROR:"):
            self.log_vuln("SSL certificate verification failed")
            self.log_info("Try running with -k flag to skip SSL verification")
            results['risk_level'] = 'SSL Error'
            results['ssl_error'] = True
            return results
        
        if signup_ui_accessible:
            self.log_info(signup_ui_msg)
        else:
            self.log_info(signup_ui_msg)
        
        # Check 2: Basic Auth API accessible (the real test)
        basic_auth_api, basic_api_msg = self.check_basic_auth()
        results['checks']['basic_auth_api'] = {
            'status': basic_auth_api,
            'message': basic_api_msg
        }
        
        if basic_auth_api:
            self.log_vuln(basic_api_msg)
        elif basic_auth_api is False:
            self.log_safe(basic_api_msg)
            results['risk_level'] = 'Low'
            return results
        else:
            self.log_info(basic_api_msg)
        
        # Check 3: Is signup disabled/hidden in UI?
        signup_hidden, signup_hidden_msg = self.check_signup_disabled()
        results['checks']['signup_ui_hidden'] = {
            'status': signup_hidden,
            'message': signup_hidden_msg
        }
        
        if signup_hidden:
            self.log_info(signup_hidden_msg)
        else:
            self.log_info(signup_hidden_msg)
        
        # Determine vulnerability
        if basic_auth_api:
            if signup_hidden:
                # UI disabled but API works = VULNERABLE TARGET
                results['vulnerable'] = True
                results['risk_level'] = 'Critical'
            else:
                # UI enabled and API works = ATTACK SOURCE
                # Can be used to register on OTHER vulnerable instances
                results['attack_source'] = True
                results['risk_level'] = 'Attack Source'
        else:
            results['risk_level'] = 'Low'
        
        return results


def print_results(results: dict):
    """Print vulnerability assessment results."""
    print(f"\n{Fore.CYAN}{'='*70}")
    print("VULNERABILITY ASSESSMENT RESULTS")
    print(f"{'='*70}{Style.RESET_ALL}\n")

    print(f"Target: {results['url']}\n")

    # Risk level
    if results['risk_level'] == 'Critical':
        print(f"Risk Level: {Fore.RED}CRITICAL - VULNERABLE TO SIGNUP BYPASS{Style.RESET_ALL}")
    elif results['risk_level'] == 'Attack Source':
        print(f"Risk Level: {Fore.YELLOW}ATTACK SOURCE - CAN BE USED FOR CROSS-TENANT BYPASS{Style.RESET_ALL}")
    elif results['risk_level'] == 'SSL Error':
        print(f"Risk Level: {Fore.RED}UNKNOWN - SSL ERROR PREVENTED SCAN{Style.RESET_ALL}")
    elif results['risk_level'] == 'High':
        print(f"Risk Level: {Fore.RED}HIGH - LIKELY VULNERABLE{Style.RESET_ALL}")
    elif results['risk_level'] == 'Medium':
        print(f"Risk Level: {Fore.YELLOW}MEDIUM - BASIC AUTH ENABLED{Style.RESET_ALL}")
    else:
        print(f"Risk Level: {Fore.GREEN}LOW - LIKELY NOT VULNERABLE{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Detailed Checks:{Style.RESET_ALL}\n")

    for check_name, check_data in results['checks'].items():
        status = check_data['status']
        message = check_data['message']

        # Clean up SSL error messages for display
        if message.startswith("SSL_ERROR:"):
            message = "SSL certificate verification failed"

        if status is True:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} {check_name}: {message}")
        elif status is False:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {check_name}: {message}")
        else:
            print(f"  {Fore.YELLOW}[?]{Style.RESET_ALL} {check_name}: {message}")

    # Recommendations
    print(f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}\n")

    if results['vulnerable']:
        if results['risk_level'] == 'Critical':
            print(f"{Fore.RED}CRITICAL: SIGNUP BYPASS VULNERABILITY CONFIRMED{Style.RESET_ALL}\n")
            print("The Basic Auth signup API is accessible even though UI hides signup.")
            print("Attackers can register accounts by calling the API directly.\n")
            print("Immediate actions:")
            print("  1. DISABLE Basic Authentication in Azure Portal immediately")
            print("  2. Audit all developer portal user accounts for unauthorized signups")
            print("  3. Review user creation logs - check for API-based registrations")
            print("  4. Implement Azure AD authentication only")
        else:
            print(f"{Fore.YELLOW}MEDIUM RISK: BASIC AUTH ENABLED{Style.RESET_ALL}\n")
            print("Basic Authentication is intentionally enabled (signup visible in UI).")
            print("This is a configuration choice but increases attack surface.\n")
            print("Recommended actions:")
            print("  1. Consider migrating to Azure AD authentication")
            print("  2. Implement email domain whitelisting")
            print("  3. Monitor signup activity for suspicious registrations")
        
        print("\nLong-term solution:")
        print("  - Migrate to Azure AD authentication")
        print("  - Disable Basic Auth (after migration planning)")
        print("  - Enable MFA for all portal users")
    elif results.get('attack_source'):
        print(f"{Fore.YELLOW}ATTACK SOURCE IDENTIFIED{Style.RESET_ALL}\n")
        print("This instance has Basic Auth signup ENABLED.")
        print("It can be used to perform cross-tenant signup bypass attacks")
        print("against OTHER APIM instances that have signup 'disabled' in UI.\n")
        print("How the attack works:")
        print("  1. Attacker uses this instance's signup form")
        print("  2. Intercepts the signup request")
        print("  3. Modifies target to another APIM instance's API endpoint")
        print("  4. Creates unauthorized account on target instance\n")
        print("If this is your instance:")
        print("  - This is a potential liability")
        print("  - Consider disabling Basic Auth if not needed")
        print("  - Or ensure proper email domain restrictions")
    elif results.get('ssl_error'):
        print(f"{Fore.RED}SSL CERTIFICATE ERROR{Style.RESET_ALL}\n")
        print("Could not connect to target due to SSL certificate verification failure.")
        print("This may be due to:")
        print("  - Self-signed certificate")
        print("  - Expired certificate")
        print("  - Corporate proxy/firewall interception")
        print("  - Missing intermediate certificates\n")
        print(f"To scan anyway, run with {Fore.YELLOW}-k{Style.RESET_ALL} flag:")
        print(f"  python apim_vuln_checker.py -k {results['url']}")
    else:
        print(f"{Fore.GREEN}Your instance appears to have reduced risk.{Style.RESET_ALL}")
        print("However, continue monitoring:")
        print("  - Review user accounts periodically")
        print("  - Monitor Azure APIM security advisories")
        print("  - Keep authentication configuration secure")

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Check if Azure APIM instance is vulnerable to cross-tenant signup bypass'
    )

    parser.add_argument(
        'url',
        help='APIM Developer Portal URL (e.g., https://your-apim.developer.azure-api.net)'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show all endpoints being checked'
    )

    parser.add_argument(
        '-k', '--insecure',
        action='store_true',
        help='Skip SSL certificate verification'
    )

    args = parser.parse_args()

    # Banner
    print(f"{Fore.CYAN}")
    print(r"""
   ___                 __              ____      
  / _ )___  __ _____  / /___ ____ __  / __ \__ __
 / _  / _ \/ // / _ \/ __/ // / // / / /_/ / // /
/____/\___/\_,_/_//_/\__/\_, /\_, /  \____/\_, / 
                        /___//___/        /___/  
    """)
    print(f"    Author: Mihalis Haatainen, Bountyy Oy - www.bountyy.fi{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print("Azure APIM Vulnerability Checker")
    print("Cross-Tenant Signup Bypass Detection")
    print(f"{'=' * 70}{Style.RESET_ALL}\n")

    # Run checks
    checker = APIMVulnerabilityChecker(args.url, verbose=args.verbose, verify_ssl=not args.insecure)
    results = checker.check_vulnerability()

    # Output results
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    else:
        print_results(results)

    # Exit code based on vulnerability
    exit(0 if not results['vulnerable'] else 1)


if __name__ == '__main__':
    main()
