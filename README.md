# Azure APIM Cross-Tenant Signup Bypass

> **Status (01.12.2025):** This vulnerability is still live and exploitable. Microsoft has not patched this issue and considers it "by design."

## Security Advisory

**[GHSA-vcwf-73jp-r7mv](https://github.com/bountyyfi/Azure-APIM-Cross-Tenant-Signup-Bypass/security/advisories/GHSA-vcwf-73jp-r7mv)**

**[CVE-2025-66390](https://www.cve.org/CVERecord?id=CVE-2025-66390)**

## Summary

A security vulnerability in Azure API Management (APIM) Developer Portal allows attackers to register accounts on any APIM instance that has Basic Authentication enabled, even when administrators have disabled user signup in the portal UI.

This bypass enables cross-tenant account creation, potentially allowing unauthorized access to API documentation, subscription keys, and other resources exposed through the Developer Portal.

## Disclosure Timeline

|Date      |Action                                                 |
|----------|-------------------------------------------------------|
|2025-09-30|Vulnerability discovered                               |
|2025-09-30|Initial report submitted to MSRC                       |
|2025-10-30|MSRC response: Closed as "not a vulnerability"         |
|2025-11-01|Second report submitted to MSRC with additional details|
|2025-11-20|MSRC response: Closed as "by design"                   |
|2025-11-20|Reported to CERT-FI                                    |
|2025-11-26|Public disclosure                                      |
|2025-11-27|CVE requested from MITRE                               |
|2026-07-09|CVE-2025-66390 assigned by MITRE TL-Root/CNA-LR        |

## Vulnerability Details

### The Issue

When Azure APIM is configured with Basic Authentication for the Developer Portal, administrators can disable user registration through the Azure Portal UI. However, this only hides the signup form in the portal interface.

The underlying signup API endpoint remains active and accepts registration requests directly, bypassing the UI restriction entirely.

### Root Cause

Two issues combine to create this vulnerability:

1. **UI-only restriction**: Disabling signup only hides the form in the portal UI. The backend signup API remains active and accessible.
1. **No tenant validation**: The signup API does not validate that the request originates from the same tenant’s portal. Requests can be crafted from any source to register on any vulnerable instance.

### Attack Vector

The attack requires two APIM instances:

1. **Attacker’s instance**: Any APIM Developer Portal with signup enabled (or attacker’s own APIM instance)
1. **Target instance**: Victim’s APIM Developer Portal with signup “disabled” in UI but Basic Authentication still configured

**Steps:**

1. Attacker accesses their own APIM Developer Portal signup page (where signup is enabled)
1. Attacker fills in the signup form and intercepts the request (e.g., using Burp Suite)
1. Attacker changes the `Host` header from their instance to the target instance
1. Attacker submits the modified request
1. Account is created on the target instance despite signup being “disabled” in their admin console
1. Attacker gains access to the target Developer Portal as a registered user

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
- **Internal portal exposure** - external attackers can register on “internal” portals

## Affected Configurations

Your APIM instance is vulnerable if:

- Basic Authentication identity provider is configured (even if signup is “disabled” in UI)
- The Developer Portal is deployed and accessible

Your APIM instance is NOT vulnerable if:

- Basic Authentication identity provider is completely removed (not just signup disabled)
- Only Azure AD / OAuth authentication is configured
- Developer Portal is not deployed or is disabled

**Key point:** Disabling signup in the Azure Portal UI is NOT sufficient. The Basic Authentication identity provider must be completely removed to prevent cross-tenant signup bypass.

## Azure Resource Properties

Use these property values to identify vulnerable APIM instances via Azure Resource Graph, ARM templates, or Azure Policy.

### Vulnerable Configuration Properties

| Property Path | Vulnerable Value | Description |
|---------------|------------------|-------------|
| `properties.developerPortalStatus` | `Enabled` | Developer Portal is accessible |
| `sku.name` | `Developer`, `Basic`, `Standard`, `Premium` | Non-Consumption tiers (Consumption tier has limited portal features) |

### Identity Provider Check (Sub-resource)

The Basic Authentication identity provider is a separate resource under the APIM instance:

```
Resource Type: Microsoft.ApiManagement/service/identityProviders
Name: basic
```

**Vulnerable if exists:** The presence of a `basic` identity provider resource indicates Basic Authentication is configured.

### Portal Signup Settings (Sub-resource)

```
Resource Type: Microsoft.ApiManagement/service/portalsettings/signup
Property: properties.enabled
```

| Property | Value | Meaning |
|----------|-------|---------|
| `properties.enabled` | `true` | Signup visible in UI |
| `properties.enabled` | `false` | Signup hidden in UI (API still works if Basic Auth exists!) |

### Azure Resource Graph Query

Use this query to find potentially vulnerable APIM instances:

```kusto
resources
| where type == "microsoft.apimanagement/service"
| where properties.developerPortalStatus == "Enabled"
| where sku.name != "Consumption"
| project name, resourceGroup, subscriptionId, location, sku.name, properties.developerPortalStatus
```

To check for Basic Auth identity providers:

```kusto
resources
| where type == "microsoft.apimanagement/service/identityproviders"
| where name endswith "/basic"
| project apimInstance=tostring(split(id, "/providers/Microsoft.ApiManagement/service/")[1]), resourceGroup, subscriptionId
```

### Azure CLI Commands

Check Developer Portal status:
```bash
az apim show --name <apim-name> --resource-group <rg-name> --query "{name:name, portalStatus:developerPortalStatus, sku:sku.name}"
```

List identity providers (check for 'basic'):
```bash
az apim identity-provider list --resource-group <rg-name> --service-name <apim-name> --query "[].name"
```

Check signup settings:
```bash
az rest --method get --url "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/<rg-name>/providers/Microsoft.ApiManagement/service/<apim-name>/portalsettings/signup?api-version=2022-08-01" --query "properties.enabled"
```

### Summary Table

| Condition | Property/Resource | Vulnerable Value |
|-----------|-------------------|------------------|
| Portal enabled | `properties.developerPortalStatus` | `== 'Enabled'` |
| Non-Consumption SKU | `sku.name` | `!= 'Consumption'` |
| Basic Auth exists | `identityProviders/basic` resource | Resource exists |
| Signup hidden (bypass possible) | `portalsettings/signup.properties.enabled` | `== false` (with Basic Auth) |

**Critical combination:** An instance is vulnerable to signup bypass when:
- `properties.developerPortalStatus == 'Enabled'` AND
- `identityProviders/basic` resource exists AND
- `portalsettings/signup.properties.enabled == false`

## Identifying Your Organization's APIM Instances

> **LEGAL DISCLAIMER:** The information below is provided solely for identifying and securing your own organization's Azure APIM instances. Unauthorized access to computer systems is illegal. Only test systems you own or have explicit written authorization to test.

### Google Dorks

**Find portals with Basic Auth signup (most likely vulnerable):**
```
site:developer.azure-api.net "Sign up" "Email" "Password"
```

```
site:developer.azure-api.net "Create account" "Username"
```

```
site:developer.azure-api.net inurl:/signup "register"
```

**Find portals with signin pages (indicates Basic Auth may be configured):**
```
site:developer.azure-api.net "Sign in" "Email" "Password" -"Azure AD" -"Microsoft account"
```

```
site:developer.azure-api.net inurl:/signin "password"
```

**Find developer portals with exposed API documentation:**
```
site:developer.azure-api.net inurl:/apis "Subscribe"
```

```
site:developer.azure-api.net "API" "Products" "Subscribe"
```

**General discovery:**
```
site:*.developer.azure-api.net
```

```
inurl:developer.azure-api.net "Developer Portal"
```

### Shodan

**Find APIM Developer Portals:**
```
http.title:"Developer Portal" http.html:"azure-api.net"
```

```
ssl.cert.subject.cn:"*.developer.azure-api.net"
```

```
http.html:"developerPortal" http.html:"azure"
```

### Nuclei Mass Scan

After discovering targets, scan with Nuclei:
```bash
# Save targets to file
echo "https://target1.developer.azure-api.net" > targets.txt
echo "https://target2.developer.azure-api.net" >> targets.txt

# Mass scan
nuclei -t azure-apim-signup-bypass.yaml -l targets.txt -o vulnerable.txt
```

### Asset Discovery for Your Organization

If your organization uses Azure APIM, you can identify your own instances using:

**Azure Portal:**
- Navigate to Azure Portal → All Resources → Filter by "API Management"
- Or use Azure Resource Graph Explorer with the queries in the previous section

**Azure CLI (for your subscriptions):**
```bash
# List all APIM instances in your subscriptions
az apim list --query "[].{name:name, resourceGroup:resourceGroup, url:developerPortalUrl}"
```

### Verifying Your Own Instances

Use these methods to check if YOUR organization's APIM instances are vulnerable:

**Using the verification script:**
```bash
# Check your own instance
python apim_vuln_checker.py https://YOUR-ORG.developer.azure-api.net

# With Azure RM property checks (recommended for internal audits)
python apim_vuln_checker.py --azure -s YOUR-SUB-ID -g YOUR-RG -n YOUR-APIM-NAME
```

**Using Nuclei for internal security audits:**
```bash
# Scan your organization's APIM instances
nuclei -t azure-apim-signup-bypass.yaml -u https://YOUR-ORG.developer.azure-api.net
```

### Indicators of Vulnerable Configuration

When auditing your own instances, look for:

- Developer Portal shows "Sign up" with Email/Password fields (not just "Sign in with Microsoft")
- Basic Authentication identity provider is configured in Azure Portal
- Signup is "disabled" in UI but Basic Auth provider still exists

**NOT vulnerable indicators:**
- Only "Sign in with Microsoft" or "Azure AD" options visible
- No Basic Authentication identity provider configured
- Developer Portal is disabled entirely

### Authorized Penetration Testing

If you are a security professional conducting authorized testing:

1. Ensure you have **written authorization** from the system owner
2. Document the scope and boundaries of your engagement
3. Follow responsible disclosure practices
4. Report findings to the organization, not publicly exploit them

### Responsible Disclosure

If you discover a vulnerable third-party APIM instance:

1. **DO NOT** attempt to create accounts or access the system
2. Contact the organization's security team directly
3. Provide them with this advisory so they can remediate
4. Allow reasonable time for remediation before any disclosure

## Verification Script

A Python script is provided to check if your APIM instance is vulnerable.

### Installation

```bash
# Basic installation (HTTP probe only)
pip install requests colorama

# Full installation (includes Azure RM property checks)
pip install requests colorama azure-identity
```

### Usage

The script supports two modes:
1. **HTTP Probe** - External black-box check via Developer Portal endpoints
2. **Azure RM Check** - Internal property check via Azure Resource Manager API

```bash
# HTTP probe (external check)
python apim_vuln_checker.py https://your-apim.developer.azure-api.net

# Azure RM property check (requires az login)
python apim_vuln_checker.py --azure -s <subscription-id> -g <resource-group> -n <apim-name>

# Combined check (both HTTP probe and Azure RM)
python apim_vuln_checker.py https://your-apim.developer.azure-api.net \
    --azure -s <subscription-id> -g <resource-group> -n <apim-name>

# Verbose output
python apim_vuln_checker.py https://your-apim.developer.azure-api.net -v

# Skip SSL verification
python apim_vuln_checker.py https://your-apim.developer.azure-api.net -k

# JSON output
python apim_vuln_checker.py https://your-apim.developer.azure-api.net --json
```

### Azure RM Property Checks

When using `--azure` mode, the script queries the Azure Resource Manager API directly to check:

| Property | Vulnerable Value |
|----------|------------------|
| `properties.developerPortalStatus` | `== 'Enabled'` |
| `sku.name` | `!= 'Consumption'` |
| `identityProviders/basic` resource | Exists |
| `portalsettings/signup.properties.enabled` | `== false` |

**Prerequisites for Azure RM mode:**
1. Install `azure-identity`: `pip install azure-identity`
2. Authenticate with Azure: `az login`
3. Ensure you have Reader access to the APIM resource

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
- Delete the “Username and password” identity provider entirely
- Note: Simply disabling signup in UI is NOT sufficient
1. **Audit existing accounts**:
- Review all Developer Portal user accounts
- Look for accounts created via API (check creation timestamps and patterns)
- Remove any unauthorized accounts
1. **Enable Azure AD authentication**:
- Configure Azure AD as the sole identity provider
- This enforces proper tenant boundaries

### Long-term Recommendations

- Use Azure AD authentication exclusively
- Do not rely on UI-level signup restrictions
- Monitor Developer Portal signup activity
- Regularly audit portal user accounts

## Microsoft’s Response

Microsoft Security Response Center (MSRC) was notified twice about this vulnerability. Both reports were closed with the following determination:

> “By design”

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

- [Blog Post: When “Disabled” Doesn’t Mean Disabled](https://www.itewiki.fi/p/when-disabled-doesn-t-mean-disabled-azure-apim-cross-tenant-signup-bypass)
- [Azure API Management Documentation](https://docs.microsoft.com/en-us/azure/api-management/)
- [APIM Developer Portal Overview](https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-developer-portal)
