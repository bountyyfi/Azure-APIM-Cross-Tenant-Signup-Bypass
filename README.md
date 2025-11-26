# Azure APIM Cross-Tenant Signup Bypass

## Summary

A security vulnerability in Azure API Management (APIM) Developer Portal allows attackers to register accounts on any APIM instance that has Basic Authentication enabled, even when administrators have disabled user signup in the portal UI.

This bypass enables cross-tenant account creation, potentially allowing unauthorized access to API documentation, subscription keys, and other resources exposed through the Developer Portal.

## Disclosure Timeline

| Date | Action |
|------|--------|
| 2025-09-30 | Vulnerability discovered |
| 2025-09-30 | Initial report submitted to MSRC |
| 2025-10-30 | MSRC response: Closed as "not a security vulnerability" |
| 2025-11-01 | Second report submitted to MSRC with additional details |
| 2025-11-20 | MSRC response: Closed as "by design, not a security vulnerability" |
| 2025-11-20 | Reported to CERT-FI |
| 2025-11-26 | Public disclosure |

## Vulnerability Details

### The Issue

When Azure APIM is configured with Basic Authentication for the Developer Portal, administrators can disable user registration through the Azure Portal UI. However, this only hides the signup form in the portal interface.

The underlying signup API endpoint remains active and accepts registration requests directly, bypassing the UI restriction entirely.

### Root Cause

Two issues combine to create this vulnerability:

1. **UI-only restriction**: Disabling signup only hides the form in the portal UI. The backend signup API remains active and accessible.

2. **No tenant validation**: The signup API does not validate that the request originates from the same tenant's portal. Requests can be crafted from any source to register on any vulnerable instance.

### Attack Vector

The attack requires two APIM instances:

1. **Attacker's instance**: Any APIM Developer Portal with signup enabled (or attacker's own APIM instance)
2. **Target instance**: Victim's APIM Developer Portal with signup "disabled" in UI but Basic Authentication still configured

**Steps:**

1. Attacker accesses their own APIM Developer Portal signup page (where signup is enabled)
2. Attacker fills in the signup form and intercepts the request (e.g., using Burp Suite)
3. Attacker changes the `Host` header from their instance to the target instance
4. Attacker submits the modified request
5. Account is created on the target instance despite signup being "disabled" in their admin console
6. Attacker gains access to the target Developer Portal as a registered user

**Key technical detail:** The cross-tenant bypass works by manipulating the `Host` header in the signup POST request. The `/signup` endpoint processes requests based on the Host header without validating tenant boundaries.

Example request manipulation:
```
POST /signup HTTP/1.1
Host: target-apim.developer.azure-api.net   <-- Changed from attacker's instance
Origin: https://attacker-apim.developer.azure-api.net
Content-Type: application/json

{"challenge":{...},"signupData":{"email":"attacker@email.com",...}}
```

The core issue: disabling signup in the UI does not disable the underlying API. The API endpoint accepts cross-tenant requests based on the Host header.

## Impact

- **Cross-tenant account creation** - register on any APIM instance with Basic Auth enabled
- **Bypass of administrative controls** - signup restrictions are ineffective
- **Access to API documentation** that may contain sensitive internal information
- **Potential to request API subscription keys** depending on portal configuration
- **Internal portal exposure** - external attackers can register on "internal" portals

## Affected Configurations

Your APIM instance is vulnerable if:

- Basic Authentication identity provider is configured (even if signup is "disabled" in UI)
- The Developer Portal is deployed and accessible

Your APIM instance is NOT vulnerable if:

- Basic Authentication identity provider is completely removed (not just signup disabled)
- Only Azure AD / OAuth authentication is configured
- Developer Portal is not deployed or is disabled

**Key point:** Disabling signup in the Azure Portal UI is NOT sufficient. The Basic Authentication identity provider must be completely removed to prevent cross-tenant signup bypass.

## Verification Script

A Python script is provided to check if your APIM instance is vulnerable.

### Installation

```bash
pip install requests colorama
```

### Usage

```bash
python apim_vuln_checker.py https://your-apim.developer.azure-api.net

# Verbose output
python apim_vuln_checker.py https://your-apim.developer.azure-api.net -v

# Skip SSL verification
python apim_vuln_checker.py https://your-apim.developer.azure-api.net -k

# JSON output
python apim_vuln_checker.py https://your-apim.developer.azure-api.net --json
```

### Example Output

```
   ___                 __              ____      
  / _ )___  __ _____  / /___ ____ __  / __ \__ __
 / _  / _ \/ // / _ \/ __/ // / // / / /_/ / // /
/____/\___/\_,_/_//_/\__/\_, /\_, /  \____/\_, / 
                        /___//___/        /___/  
    
    Author: Mihalis Haatainen, Bountyy Oy - www.bountyy.fi

======================================================================
Azure APIM Vulnerability Checker
Cross-Tenant Signup Bypass Detection
======================================================================

[?] Checking signup endpoint accessibility...
[i] Signup endpoint is accessible
[?] Checking if Basic Auth signup API is accessible...
[!] Basic Auth signup API ACTIVE (captcha validation)
[?] Checking if signup is hidden/disabled in UI...
[i] Signup page returns 404 (hidden in UI)

======================================================================
VULNERABILITY ASSESSMENT RESULTS
======================================================================

Target: https://example.developer.azure-api.net

Risk Level: CRITICAL - VULNERABLE TO SIGNUP BYPASS

Detailed Checks:

  [!] signup_ui: Signup endpoint is accessible
  [!] basic_auth_api: Basic Auth signup API ACTIVE (captcha validation)
  [+] signup_ui_hidden: Signup page returns 404 (hidden in UI)

Recommendations:

CRITICAL: SIGNUP BYPASS VULNERABILITY CONFIRMED

The Basic Auth signup API is accessible even though UI hides signup.
Attackers can register accounts by calling the API directly.

Immediate actions:
  1. DISABLE Basic Authentication in Azure Portal immediately
  2. Audit all developer portal user accounts for unauthorized signups
  3. Review user creation logs - check for API-based registrations
  4. Implement Azure AD authentication only
```

## Nuclei Template

A Nuclei template is provided for automated scanning.

### Usage

```bash
# Single target
nuclei -t azure-apim-signup-bypass.yaml -u https://target.developer.azure-api.net

# Multiple targets from file
nuclei -t azure-apim-signup-bypass.yaml -l targets.txt

# With proxy (for debugging)
nuclei -t azure-apim-signup-bypass.yaml -u https://target.developer.azure-api.net -proxy http://127.0.0.1:8080

# Skip SSL verification
nuclei -t azure-apim-signup-bypass.yaml -u https://target.developer.azure-api.net -insecure
```

### Template Details

- Sends POST request to `/signup` endpoint with test captcha data
- Detects active signup API by checking for captcha/validation error responses
- CVSS Score: 6.5 (Medium-High)
- CWE-284: Improper Access Control

## Mitigation

### Immediate Actions

1. **Remove Basic Authentication identity provider completely** in Azure Portal:
   - Navigate to your APIM instance
   - Go to Developer Portal -> Identities
   - Delete the "Username and password" identity provider entirely
   - Note: Simply disabling signup in UI is NOT sufficient

2. **Audit existing accounts**:
   - Review all Developer Portal user accounts
   - Look for accounts created via API (check creation timestamps and patterns)
   - Remove any unauthorized accounts

3. **Enable Azure AD authentication**:
   - Configure Azure AD as the sole identity provider
   - This enforces proper tenant boundaries

### Long-term Recommendations

- Use Azure AD authentication exclusively
- Do not rely on UI-level signup restrictions
- Monitor Developer Portal signup activity
- Regularly audit portal user accounts

## Microsoft's Response

Microsoft Security Response Center (MSRC) was notified twice about this vulnerability. Both reports were closed with the following determination:

> "By design"

MSRC does not consider this a security vulnerability despite the bypass of administrative controls and cross-tenant implications.

## Files

- `apim_vuln_checker.py` - Python vulnerability verification script
- `azure-apim-signup-bypass.yaml` - Nuclei template for automated scanning
- `README.md` - This file

## Author

**Mihalis Haatainen**  
Bountyy Oy - Finnish penetration testing and security research company

- Website: [www.bountyy.fi](https://www.bountyy.fi)

## License

This advisory and associated tools are released for defensive purposes. Use responsibly.

MIT License - See LICENSE file for details.

## References

- [Azure API Management Documentation](https://docs.microsoft.com/en-us/azure/api-management/)
- [APIM Developer Portal Overview](https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-developer-portal)
