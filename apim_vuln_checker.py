#!/usr/bin/env python3
"""
Azure APIM Vulnerability Verification Script
Checks if an APIM instance is vulnerable to cross-tenant signup bypass

Author: Mihalis Haatainen, Bountyy Oy, www.bountyy.fi
Date: November 26, 2025
"""

import argparse
import requests
from colorama import Fore, Style, init
from typing import Tuple, Optional, Dict, Any

init(autoreset=True)

# Azure RM API version for APIM
APIM_API_VERSION = "2022-08-01"


class AzureRMChecker:
    """Check APIM properties directly via Azure Resource Manager API."""

    def __init__(self, subscription_id: str, resource_group: str, service_name: str, verbose: bool = False):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.service_name = service_name
        self.verbose = verbose
        self.base_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.ApiManagement/service/{service_name}"
        self.token = None

    def log_check(self, message: str):
        print(f"{Fore.BLUE}[?]{Style.RESET_ALL} {message}")

    def log_vuln(self, message: str):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {message}")

    def log_safe(self, message: str):
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {message}")

    def log_info(self, message: str):
        print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} {message}")

    def get_azure_token(self) -> Optional[str]:
        """Get Azure access token using DefaultAzureCredential."""
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
            token = credential.get_token("https://management.azure.com/.default")
            return token.token
        except ImportError:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} azure-identity package not installed.")
            print(f"    Install with: pip install azure-identity")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to get Azure token: {e}")
            print(f"    Make sure you're logged in with: az login")
            return None

    def _make_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Make authenticated request to Azure RM API."""
        if not self.token:
            self.token = self.get_azure_token()
            if not self.token:
                return None

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            if self.verbose:
                print(f"    GET {url}")
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"_not_found": True}
            else:
                if self.verbose:
                    print(f"    -> {response.status_code}: {response.text[:200]}")
                return None
        except Exception as e:
            if self.verbose:
                print(f"    -> Error: {e}")
            return None

    def check_apim_properties(self) -> Tuple[Optional[bool], str, Dict[str, Any]]:
        """
        Check APIM service properties.

        Returns:
            Tuple of (is_vulnerable_config, message, properties_dict)
        """
        self.log_check("Checking APIM service properties via Azure RM...")

        url = f"{self.base_url}?api-version={APIM_API_VERSION}"
        data = self._make_request(url)

        if data is None:
            return None, "Failed to query APIM properties", {}

        if data.get("_not_found"):
            return None, "APIM service not found", {}

        properties = data.get("properties", {})
        sku = data.get("sku", {})

        result = {
            "developerPortalStatus": properties.get("developerPortalStatus"),
            "sku_name": sku.get("name"),
            "sku_tier": sku.get("tier"),
        }

        # Check vulnerable conditions
        portal_enabled = properties.get("developerPortalStatus") == "Enabled"
        is_consumption = sku.get("name") == "Consumption"

        if portal_enabled:
            self.log_vuln(f"properties.developerPortalStatus = 'Enabled'")
        else:
            self.log_safe(f"properties.developerPortalStatus = '{properties.get('developerPortalStatus')}'")

        if is_consumption:
            self.log_safe(f"sku.name = 'Consumption' (limited portal features)")
        else:
            self.log_info(f"sku.name = '{sku.get('name')}' (full portal features)")

        return portal_enabled and not is_consumption, "APIM properties checked", result

    def check_basic_identity_provider(self) -> Tuple[Optional[bool], str]:
        """
        Check if Basic Authentication identity provider exists.

        Returns:
            Tuple of (exists, message)
        """
        self.log_check("Checking for Basic Auth identity provider...")

        url = f"{self.base_url}/identityProviders/basic?api-version={APIM_API_VERSION}"
        data = self._make_request(url)

        if data is None:
            return None, "Failed to query identity providers"

        if data.get("_not_found"):
            self.log_safe("identityProviders/basic does NOT exist")
            return False, "Basic Auth identity provider not configured"

        self.log_vuln("identityProviders/basic EXISTS - Basic Auth is configured!")
        return True, "Basic Auth identity provider is configured"

    def check_signup_settings(self) -> Tuple[Optional[bool], str, Optional[bool]]:
        """
        Check portal signup settings.

        Returns:
            Tuple of (signup_disabled_in_ui, message, enabled_value)
        """
        self.log_check("Checking portal signup settings...")

        url = f"{self.base_url}/portalsettings/signup?api-version={APIM_API_VERSION}"
        data = self._make_request(url)

        if data is None:
            return None, "Failed to query signup settings", None

        if data.get("_not_found"):
            return None, "Signup settings not found", None

        properties = data.get("properties", {})
        enabled = properties.get("enabled")

        if enabled is True:
            self.log_info("portalsettings/signup.properties.enabled = true (signup visible in UI)")
            return False, "Signup is enabled in UI", True
        elif enabled is False:
            self.log_vuln("portalsettings/signup.properties.enabled = false (signup hidden but API may still work!)")
            return True, "Signup is HIDDEN in UI (bypass possible)", False
        else:
            return None, f"Signup enabled value: {enabled}", enabled

    def check_vulnerability(self) -> Dict[str, Any]:
        """
        Perform comprehensive Azure RM property checks.

        Returns:
            Dictionary with all check results and vulnerability assessment
        """
        results = {
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "service_name": self.service_name,
            "vulnerable": False,
            "risk_level": "Unknown",
            "checks": {},
            "properties": {}
        }

        # Check 1: APIM service properties
        props_vuln, props_msg, props_data = self.check_apim_properties()
        results["checks"]["apim_properties"] = {
            "status": props_vuln,
            "message": props_msg
        }
        results["properties"].update(props_data)

        if props_vuln is None:
            results["risk_level"] = "Error"
            return results

        # Check 2: Basic Auth identity provider
        basic_exists, basic_msg = self.check_basic_identity_provider()
        results["checks"]["basic_auth_provider"] = {
            "status": basic_exists,
            "message": basic_msg
        }
        results["properties"]["basic_auth_exists"] = basic_exists

        if basic_exists is None:
            results["risk_level"] = "Error"
            return results

        if not basic_exists:
            results["risk_level"] = "Low"
            results["checks"]["assessment"] = {
                "status": False,
                "message": "No Basic Auth configured - not vulnerable"
            }
            return results

        # Check 3: Signup settings (only relevant if Basic Auth exists)
        signup_hidden, signup_msg, signup_enabled = self.check_signup_settings()
        results["checks"]["signup_settings"] = {
            "status": signup_hidden,
            "message": signup_msg
        }
        results["properties"]["signup_enabled"] = signup_enabled

        # Determine vulnerability
        if props_vuln and basic_exists:
            if signup_hidden:
                # Critical: Portal enabled + Basic Auth exists + Signup hidden = VULNERABLE
                results["vulnerable"] = True
                results["risk_level"] = "Critical"
                results["checks"]["assessment"] = {
                    "status": True,
                    "message": "VULNERABLE: Signup hidden in UI but Basic Auth API still accessible"
                }
            else:
                # Basic Auth enabled and signup visible - attack source
                results["risk_level"] = "Attack Source"
                results["checks"]["assessment"] = {
                    "status": True,
                    "message": "Basic Auth signup enabled - can be used for cross-tenant attacks"
                }
        else:
            results["risk_level"] = "Low"
            results["checks"]["assessment"] = {
                "status": False,
                "message": "Configuration appears safe"
            }

        return results


def print_azure_rm_results(results: Dict[str, Any]):
    """Print Azure RM check results."""
    print(f"\n{Fore.CYAN}{'='*70}")
    print("AZURE RESOURCE MANAGER PROPERTY CHECK RESULTS")
    print(f"{'='*70}{Style.RESET_ALL}\n")

    print(f"Subscription: {results['subscription_id']}")
    print(f"Resource Group: {results['resource_group']}")
    print(f"Service Name: {results['service_name']}\n")

    # Risk level
    risk = results['risk_level']
    if risk == 'Critical':
        print(f"Risk Level: {Fore.RED}CRITICAL - VULNERABLE TO SIGNUP BYPASS{Style.RESET_ALL}")
    elif risk == 'Attack Source':
        print(f"Risk Level: {Fore.YELLOW}ATTACK SOURCE - CAN BE USED FOR CROSS-TENANT BYPASS{Style.RESET_ALL}")
    elif risk == 'Error':
        print(f"Risk Level: {Fore.RED}ERROR - COULD NOT COMPLETE CHECKS{Style.RESET_ALL}")
    else:
        print(f"Risk Level: {Fore.GREEN}LOW - NOT VULNERABLE{Style.RESET_ALL}")

    # Properties
    print(f"\n{Fore.CYAN}Resource Properties:{Style.RESET_ALL}\n")
    props = results.get('properties', {})
    for key, value in props.items():
        if key == 'basic_auth_exists' and value:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} {key}: {value}")
        elif key == 'signup_enabled' and value is False:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} {key}: {value}")
        elif key == 'developerPortalStatus' and value == 'Enabled':
            print(f"  {Fore.YELLOW}[i]{Style.RESET_ALL} {key}: {value}")
        else:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {key}: {value}")

    # Assessment
    print(f"\n{Fore.CYAN}Vulnerability Assessment:{Style.RESET_ALL}\n")
    for check_name, check_data in results['checks'].items():
        status = check_data['status']
        message = check_data['message']

        if status is True:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} {check_name}: {message}")
        elif status is False:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {check_name}: {message}")
        else:
            print(f"  {Fore.YELLOW}[?]{Style.RESET_ALL} {check_name}: {message}")

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


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
        description='Check if Azure APIM instance is vulnerable to cross-tenant signup bypass',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # HTTP probe (external check)
  python apim_vuln_checker.py https://your-apim.developer.azure-api.net

  # Azure RM property check (requires az login)
  python apim_vuln_checker.py --azure -s <subscription-id> -g <resource-group> -n <apim-name>

  # Combined check (both HTTP probe and Azure RM)
  python apim_vuln_checker.py https://your-apim.developer.azure-api.net --azure -s <sub> -g <rg> -n <name>
"""
    )

    parser.add_argument(
        'url',
        nargs='?',
        default=None,
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

    # Azure RM arguments
    azure_group = parser.add_argument_group('Azure Resource Manager', 'Check APIM properties directly via Azure RM API')
    azure_group.add_argument(
        '--azure',
        action='store_true',
        help='Enable Azure RM property checks (requires azure-identity package and az login)'
    )
    azure_group.add_argument(
        '-s', '--subscription',
        help='Azure subscription ID'
    )
    azure_group.add_argument(
        '-g', '--resource-group',
        help='Azure resource group name'
    )
    azure_group.add_argument(
        '-n', '--name',
        help='APIM service name'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.url and not args.azure:
        parser.error("Either URL or --azure with -s/-g/-n is required")

    if args.azure and not all([args.subscription, args.resource_group, args.name]):
        parser.error("--azure requires -s/--subscription, -g/--resource-group, and -n/--name")

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

    all_results = {}
    is_vulnerable = False

    # Run HTTP probe checks if URL provided
    if args.url:
        checker = APIMVulnerabilityChecker(args.url, verbose=args.verbose, verify_ssl=not args.insecure)
        http_results = checker.check_vulnerability()
        all_results['http_probe'] = http_results
        is_vulnerable = is_vulnerable or http_results.get('vulnerable', False)

        if not args.json:
            print_results(http_results)

    # Run Azure RM property checks if enabled
    if args.azure:
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print("AZURE RESOURCE MANAGER PROPERTY CHECKS")
        print(f"{'=' * 70}{Style.RESET_ALL}\n")

        azure_checker = AzureRMChecker(
            subscription_id=args.subscription,
            resource_group=args.resource_group,
            service_name=args.name,
            verbose=args.verbose
        )
        azure_results = azure_checker.check_vulnerability()
        all_results['azure_rm'] = azure_results
        is_vulnerable = is_vulnerable or azure_results.get('vulnerable', False)

        if not args.json:
            print_azure_rm_results(azure_results)

    # Output JSON if requested
    if args.json:
        import json
        print(json.dumps(all_results, indent=2))

    # Exit code based on vulnerability
    exit(0 if not is_vulnerable else 1)


if __name__ == '__main__':
    main()
