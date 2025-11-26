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
        except Exception as e:
            return False, f"Error accessing signup endpoint: {str(e)}"

    def get_management_url(self) -> str:
        """Convert developer portal URL to management API URL."""
        # https://xyz.developer.azure-api.net -> https://xyz.management.azure-api.net
        return self.url.replace('.developer.azure-api.net', '.management.azure-api.net')
    
    def check_basic_auth(self) -> Tuple[bool, str]:
        """Check if Basic Authentication signup API is accessible (bypassing UI)."""
        self.log_check("Checking if Basic Auth signup API is accessible...")
        
        # Test payload - obviously fake, just probing endpoint behavior
        signup_payload = {
            'email': 'vuln-probe-test@nonexistent-invalid-domain.test',
            'password': 'VulnProbe123!',
            'firstName': 'Probe',
            'lastName': 'Test'
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': self.url,
            'Referer': f'{self.url}/signup'
        }
        
        # Known APIM signup API paths to try
        api_paths = [
            # Portal API paths
            '/identity/basic/signup',
            '/api/identity/basic/signup',
            '/portal/api/identity/basic/signup',
            '/developer/identity/basic/signup', 
            '/portal/identity/basic/signup',
            '/developerportal/identity/basic/signup',
            
            # Alternative patterns
            '/identity/signup',
            '/api/identity/signup',
            '/api/signup',
            '/users/signup',
            '/account/signup',
            '/register',
            '/api/register',
            
            # Management API style
            '/users/identities/basic',
            '/subscriptions/users',
        ]
        
        management_url = self.get_management_url()
        
        # Try on both developer portal and management endpoints
        base_urls = [self.url, management_url]
        
        for base in base_urls:
            for path in api_paths:
                try:
                    api_url = f'{base}{path}'
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
                    
                    # 404 = endpoint doesn't exist, skip
                    if response.status_code == 404:
                        continue
                    
                    response_text = response.text.lower()
                    
                    # These responses indicate the signup API EXISTS and processes requests
                    if response.status_code == 400:
                        # Validation error = endpoint exists and validates input
                        if 'email' in response_text or 'password' in response_text or 'invalid' in response_text:
                            return True, f"Basic Auth signup API ACTIVE at {path}"
                        return True, f"Basic Auth signup API responds at {path} (400)"
                    
                    elif response.status_code == 409:
                        # Conflict = user exists = signup works
                        return True, f"Basic Auth signup API ACTIVE at {path} (409 conflict)"
                    
                    elif response.status_code == 200 or response.status_code == 201:
                        return True, f"Basic Auth signup API ACCEPTS requests at {path}"
                    
                    elif response.status_code == 401 or response.status_code == 403:
                        # Auth required but endpoint exists
                        continue
                    
                    elif response.status_code == 422:
                        return True, f"Basic Auth signup API validates at {path} (422)"
                    
                    else:
                        self.log_info(f"  {path} returned {response.status_code}")
                        
                except requests.exceptions.Timeout:
                    continue
                except Exception as e:
                    continue
        
        return False, "Basic Auth signup API not found or not accessible"

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

        if status is True:
            print(f"  {Fore.RED}[✗]{Style.RESET_ALL} {check_name}: {message}")
        elif status is False:
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {check_name}: {message}")
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
