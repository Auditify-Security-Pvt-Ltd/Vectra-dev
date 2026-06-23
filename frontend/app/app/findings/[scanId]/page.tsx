'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft, Copy, Check, ExternalLink, Shield, AlertTriangle,
  Target, Wrench, BookOpen, Eye, ChevronDown, ChevronUp, FileText,
  Bug, Globe, ShieldCheck,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet'
import { ScrollArea } from '@/components/ui/scroll-area'
import { listenToFindingsByScan, type FirestoreFinding } from '@/lib/firestore-findings'
import { useAuth } from '@/context/auth-context'

// ── Severity constants ────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  high:     'bg-orange-500/10 text-orange-500 border-orange-500/20',
  medium:   'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  low:      'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info:     'bg-gray-500/10 text-gray-400 border-gray-500/20',
  unknown:  'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

const SEVERITY_BAR: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-yellow-500',
  low:      'bg-blue-400',
  info:     'bg-gray-400',
  unknown:  'bg-gray-400',
}

// ── Vulnerability Metadata Engine ─────────────────────────────────────

interface CvssVector {
  score: number
  attackVector: string
  attackComplexity: string
  privilegesRequired: string
  userInteraction: string
  scope: string
  confidentiality: string
  integrity: string
  availability: string
}

interface VulnMeta {
  summary: string
  businessImpact: string[]
  cvss: CvssVector
  vectraRiskScore: number
  remediation: string[]
  references: { label: string; url: string }[]
  evidence: string[]
  affectedComponent: string
  category: string
}

const DEFAULT_CVSS: Record<string, CvssVector> = {
  critical: { score: 9.1, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'High', availability: 'High' },
  high:     { score: 7.5, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'None', availability: 'None' },
  medium:   { score: 5.3, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'Low',  integrity: 'None', availability: 'None' },
  low:      { score: 3.1, attackVector: 'Network', attackComplexity: 'High', privilegesRequired: 'None', userInteraction: 'Required', scope: 'Unchanged', confidentiality: 'None', integrity: 'Low', availability: 'None' },
  info:     { score: 0.0, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'None', integrity: 'None', availability: 'None' },
  unknown:  { score: 0.0, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'None', integrity: 'None', availability: 'None' },
}

const DEFAULT_RISK: Record<string, number> = {
  critical: 92, high: 74, medium: 51, low: 24, info: 8, unknown: 0,
}

type TemplateDef = Omit<VulnMeta, 'cvss' | 'vectraRiskScore'> & {
  cvss?: Partial<CvssVector>
  vectraRiskScore?: number
}

const TEMPLATE_DB: Record<string, TemplateDef> = {
  'vectra-clickjacking': {
    category: 'Clickjacking',
    summary: 'The application does not implement X-Frame-Options or Content-Security-Policy frame-ancestors protection. An attacker can embed this application inside a hidden iframe on a malicious website and trick authenticated users into performing unintended actions through UI redressing.',
    businessImpact: [
      'Unauthorized actions performed on behalf of authenticated users',
      'Account takeover via UI redressing attacks',
      'Phishing attacks using the legitimate application interface',
      'Financial fraud through invisible click hijacking',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['X-Frame-Options header: not present', 'Content-Security-Policy frame-ancestors directive: not present'],
    remediation: [
      "Add response header: X-Frame-Options: DENY",
      "Add Content-Security-Policy directive: frame-ancestors 'none'",
      "Configure both headers for maximum browser compatibility",
      "For same-origin framing: use X-Frame-Options: SAMEORIGIN and frame-ancestors 'self'",
    ],
    references: [
      { label: 'OWASP Clickjacking Defense Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html' },
      { label: 'CWE-1021: Improper Restriction of Rendered UI Layers', url: 'https://cwe.mitre.org/data/definitions/1021.html' },
      { label: 'MDN X-Frame-Options Documentation', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options' },
    ],
    cvss: { score: 6.5, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'Required', scope: 'Unchanged', confidentiality: 'None', integrity: 'Low', availability: 'None' },
    vectraRiskScore: 61,
  },
  'vectra-git-exposure': {
    category: 'Source Code Exposure',
    summary: 'A publicly accessible .git directory was discovered on the web server. This allows any unauthenticated attacker to reconstruct the full application source code, extract hardcoded secrets, API keys, database credentials, and internal business logic from the git history.',
    businessImpact: [
      'Full source code disclosure to any unauthenticated attacker',
      'Exposure of hardcoded credentials, API keys, and secrets in git history',
      'Internal infrastructure and architecture disclosure',
      'Competitive intelligence theft through proprietary code exposure',
      'Regulatory and compliance violations (PCI DSS, GDPR)',
    ],
    affectedComponent: 'Web Server File System',
    evidence: ['/.git/HEAD accessible', '/.git/config accessible', 'Repository metadata exposed'],
    remediation: [
      "Block access to .git directory via server configuration",
      "Nginx: add 'location ~ /\\.git { deny all; }' to server block",
      "Apache: add 'Deny from all' to .git directory in .htaccess",
      "Rotate all credentials and API keys that may have appeared in git history",
      "Use git-secrets or TruffleHog to audit history for exposed secrets",
      "Re-deploy application without .git directory in web root",
    ],
    references: [
      { label: 'OWASP Sensitive Data Exposure', url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure' },
      { label: 'CWE-538: File and Directory Information Exposure', url: 'https://cwe.mitre.org/data/definitions/538.html' },
    ],
    cvss: { score: 9.1, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'None', availability: 'None' },
    vectraRiskScore: 95,
  },
  'vectra-backup-exposure': {
    category: 'Information Disclosure',
    summary: 'A backup file was found publicly accessible on the web server. Backup files often contain full application source code, database dumps, configuration files with credentials, and other sensitive operational data that were not intended to be publicly accessible.',
    businessImpact: [
      'Exposure of database credentials and connection strings',
      'Disclosure of application source code and business logic',
      'Sensitive configuration data available to attackers',
      'Potential for further exploitation using disclosed secrets',
    ],
    affectedComponent: 'Web Server File System',
    evidence: ['Backup file accessible without authentication', 'HTTP 200 response with backup file content'],
    remediation: [
      "Remove all backup files from the web root immediately",
      "Audit web server for other backup or temporary files",
      "Implement file extension blocking for .bak, .sql, .zip, .tar.gz in web server config",
      "Store backups in a location not accessible via HTTP",
      "Rotate any credentials that may have been exposed",
    ],
    references: [
      { label: 'OWASP A05:2021 - Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
      { label: 'CWE-530: Exposure of Backup File to Unauthorized Control Sphere', url: 'https://cwe.mitre.org/data/definitions/530.html' },
    ],
    cvss: { score: 7.5, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'None', availability: 'None' },
    vectraRiskScore: 78,
  },
  'vectra-debug-endpoint': {
    category: 'Debug Endpoint Exposure',
    summary: 'A debug or diagnostic endpoint is publicly accessible on this application. Debug endpoints expose internal application state, environment variables, configuration values, loaded modules, and other sensitive operational data intended only for developers.',
    businessImpact: [
      'Disclosure of environment variables and application secrets',
      'Internal network topology and infrastructure exposure',
      'Application framework version disclosure enabling targeted attacks',
      'Configuration data enabling privilege escalation',
    ],
    affectedComponent: 'Application Endpoint',
    evidence: ['Debug endpoint accessible without authentication', 'Internal diagnostic data returned in response'],
    remediation: [
      "Disable or remove debug endpoints in production environments",
      "Restrict debug endpoints to localhost or internal IP ranges only",
      "Implement authentication and authorization on all diagnostic endpoints",
      "Audit all framework debug routes (e.g., /actuator, /debug, /console)",
      "Set appropriate environment flags (DEBUG=False, NODE_ENV=production)",
    ],
    references: [
      { label: 'OWASP A05:2021 - Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
      { label: 'CWE-200: Exposure of Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/200.html' },
    ],
    cvss: { score: 7.5, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'None', availability: 'None' },
    vectraRiskScore: 76,
  },
  'vectra-directory-listing': {
    category: 'Directory Listing',
    summary: 'Directory listing is enabled on the web server, allowing unauthenticated users to browse the contents of directories that lack an index file. This reveals the application file structure, potentially exposing sensitive files, configuration, and backup data.',
    businessImpact: [
      'Application structure and file naming convention disclosure',
      'Sensitive file discovery enabling targeted exploitation',
      'Configuration and backup file enumeration',
      'Reduced attacker effort for information gathering',
    ],
    affectedComponent: 'Web Server Configuration',
    evidence: ['Directory index response (HTTP 200 with file listing)', 'Directory contents visible without authentication'],
    remediation: [
      "Disable directory listing in web server configuration",
      "Nginx: ensure 'autoindex off' is set (this is the default)",
      "Apache: set 'Options -Indexes' in server or .htaccess configuration",
      "Add index files to all directories that must be accessible",
      "Audit all directories for inadvertently exposed sensitive files",
    ],
    references: [
      { label: 'OWASP Information Gathering: Directory Listing', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information' },
      { label: 'CWE-548: Exposure of Information Through Directory Listing', url: 'https://cwe.mitre.org/data/definitions/548.html' },
    ],
    cvss: { score: 5.3, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'Low', integrity: 'None', availability: 'None' },
    vectraRiskScore: 48,
  },
  'vectra-admin-panel': {
    category: 'Admin Panel Exposure',
    summary: 'An administrative interface was discovered publicly accessible on this application. Exposed admin panels are high-value targets for brute-force attacks, credential stuffing, and exploitation of authentication vulnerabilities, potentially leading to full system compromise.',
    businessImpact: [
      'Full application compromise if admin credentials are weak or reused',
      'Brute-force and credential stuffing attacks against admin accounts',
      'Unauthorized access to sensitive user data and business operations',
      'Potential for backdoor installation and persistent access',
    ],
    affectedComponent: 'Administrative Interface',
    evidence: ['Admin panel accessible from the internet', 'Login form present without IP restriction'],
    remediation: [
      "Restrict admin panel access to specific IP addresses or VPN",
      "Enable multi-factor authentication (MFA) for all admin accounts",
      "Implement CAPTCHA and account lockout after failed attempts",
      "Change the admin panel URL from common paths to a non-obvious path",
      "Use a Web Application Firewall (WAF) to detect and block credential attacks",
    ],
    references: [
      { label: 'OWASP A07:2021 - Identification and Authentication Failures', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
      { label: 'CWE-284: Improper Access Control', url: 'https://cwe.mitre.org/data/definitions/284.html' },
    ],
    cvss: { score: 6.5, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'Low', integrity: 'Low', availability: 'None' },
    vectraRiskScore: 67,
  },
  'vectra-missing-rate-limit': {
    category: 'Missing Rate Limiting',
    summary: 'No rate limiting mechanisms were detected on this API endpoint. Without rate limiting, attackers can perform high-volume brute-force attacks against authentication endpoints, abuse API quotas, perform denial-of-service attacks, and conduct automated enumeration attacks.',
    businessImpact: [
      'Brute-force attacks against authentication endpoints',
      'API abuse and quota exhaustion affecting legitimate users',
      'Automated enumeration of users, resources, and data',
      'Increased infrastructure costs from automated abuse',
    ],
    affectedComponent: 'API Endpoint',
    evidence: ['No rate-limiting headers detected (X-RateLimit-*, Retry-After)', 'Multiple rapid requests accepted without throttling'],
    remediation: [
      "Implement rate limiting at the API gateway or application layer",
      "Use token bucket or sliding window rate limiting algorithms",
      "Return HTTP 429 Too Many Requests with Retry-After header when limits are exceeded",
      "Apply stricter limits to authentication endpoints (login, password reset)",
      "Consider implementing CAPTCHA for sensitive operations",
    ],
    references: [
      { label: 'OWASP API4:2023 - Unrestricted Resource Consumption', url: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/' },
      { label: 'CWE-770: Allocation of Resources Without Limits', url: 'https://cwe.mitre.org/data/definitions/770.html' },
    ],
    cvss: { score: 3.7, attackVector: 'Network', attackComplexity: 'High', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'None', integrity: 'None', availability: 'Low' },
    vectraRiskScore: 28,
  },
  'vectra-sensitive-file': {
    category: 'Sensitive File Exposure',
    summary: 'A sensitive file was found publicly accessible on the web server. This file may contain credentials, configuration data, private keys, or other sensitive information that should not be publicly accessible.',
    businessImpact: [
      'Credential and API key exposure enabling further attacks',
      'Internal configuration data disclosure',
      'Private key exposure enabling traffic decryption or impersonation',
      'Compliance violations (PCI DSS, HIPAA, GDPR)',
    ],
    affectedComponent: 'Web Server File System',
    evidence: ['Sensitive file accessible without authentication', 'HTTP 200 response with sensitive content'],
    remediation: [
      "Remove or relocate the sensitive file outside the web root immediately",
      "Audit the web root for other inadvertently exposed files",
      "Implement web server deny rules for sensitive file extensions",
      "Rotate any credentials or keys that may have been exposed",
      "Review web server access logs for evidence of prior access",
    ],
    references: [
      { label: 'OWASP A05:2021 - Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
      { label: 'CWE-538: File and Directory Information Exposure', url: 'https://cwe.mitre.org/data/definitions/538.html' },
    ],
    cvss: { score: 7.5, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'None', availability: 'None' },
    vectraRiskScore: 79,
  },
  'vectra-swagger-exposure': {
    category: 'API Documentation Exposure',
    summary: 'Swagger/OpenAPI documentation was found publicly accessible. This reveals the complete API surface including all endpoints, parameters, data models, and authentication schemes. Attackers can use this to rapidly map and exploit the API without any prior reconnaissance.',
    businessImpact: [
      'Complete API attack surface disclosed to unauthenticated parties',
      'Authentication schemes and token formats exposed',
      'Internal data models and business logic revealed',
      'Reduced attacker effort for API abuse and exploitation',
    ],
    affectedComponent: 'API Documentation',
    evidence: ['Swagger UI accessible without authentication', 'OpenAPI specification retrievable at public endpoint'],
    remediation: [
      "Restrict Swagger UI and API spec access to authenticated users or internal networks",
      "Disable Swagger in production environments if not required externally",
      "Implement authentication on /swagger-ui, /api-docs, /openapi.json endpoints",
      "Use API gateway policies to restrict documentation access by IP or role",
    ],
    references: [
      { label: 'OWASP API9:2023 - Improper Inventory Management', url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/' },
      { label: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', url: 'https://cwe.mitre.org/data/definitions/200.html' },
    ],
    cvss: { score: 5.3, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'Low', integrity: 'None', availability: 'None' },
    vectraRiskScore: 52,
  },
  'vectra-missing-csp': {
    category: 'Missing Security Header',
    summary: 'The Content-Security-Policy (CSP) header is absent from HTTP responses. CSP is a critical defense-in-depth mechanism that prevents cross-site scripting (XSS), data injection attacks, and clickjacking by controlling which resources the browser is permitted to load.',
    businessImpact: [
      'Increased XSS attack surface without policy-based script restriction',
      'Data injection attacks via uncontrolled resource loading',
      'Inline script execution from injected malicious content',
      'Reduced effectiveness of other XSS mitigations',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['Content-Security-Policy header: not present in HTTP response'],
    remediation: [
      "Add Content-Security-Policy header to all HTTP responses",
      "Start with a report-only policy to identify violations: Content-Security-Policy-Report-Only",
      "Recommended base policy: default-src 'self'; script-src 'self'; object-src 'none'",
      "Use nonces or hashes for inline scripts instead of 'unsafe-inline'",
      "Configure a CSP report endpoint to monitor violations",
    ],
    references: [
      { label: 'OWASP Content Security Policy Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
      { label: 'CWE-693: Protection Mechanism Failure', url: 'https://cwe.mitre.org/data/definitions/693.html' },
      { label: 'MDN Content-Security-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy' },
    ],
    cvss: { score: 5.3, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'Low', integrity: 'None', availability: 'None' },
    vectraRiskScore: 49,
  },
  'vectra-missing-hsts': {
    category: 'Missing Security Header',
    summary: 'The HTTP Strict-Transport-Security (HSTS) header is absent. Without HSTS, browsers may accept unencrypted HTTP connections, making users vulnerable to SSL-stripping attacks where an active man-in-the-middle attacker downgrades HTTPS connections to plaintext HTTP.',
    businessImpact: [
      'User credentials and session tokens exposed over unencrypted connections',
      'Man-in-the-middle attacks via SSL stripping on public networks',
      'Cookie theft without the Secure flag being enforced',
      'Degraded encryption posture in public Wi-Fi environments',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['Strict-Transport-Security header: not present in HTTPS response'],
    remediation: [
      "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
      "After verifying no HTTP-only subdomains exist, add the preload directive",
      "Submit the domain to the HSTS Preload List at hstspreload.org",
      "Ensure all cookies are set with the Secure flag",
    ],
    references: [
      { label: 'OWASP HTTP Strict Transport Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' },
      { label: 'CWE-311: Missing Encryption of Sensitive Data', url: 'https://cwe.mitre.org/data/definitions/311.html' },
    ],
    cvss: { score: 5.9, attackVector: 'Network', attackComplexity: 'High', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'High', integrity: 'None', availability: 'None' },
    vectraRiskScore: 53,
  },
  'vectra-missing-xfo': {
    category: 'Missing Security Header',
    summary: 'The X-Frame-Options header is absent, allowing this page to be embedded in iframes on external websites. This creates a clickjacking vulnerability where attackers can overlay the application interface to trick authenticated users into unintentionally performing actions.',
    businessImpact: [
      'Clickjacking attacks tricking users into unintended actions',
      'UI redressing attacks against authenticated sessions',
      'Phishing via legitimate interface overlay',
      'Unauthorized form submissions and account modifications',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['X-Frame-Options header: not present in HTTP response'],
    remediation: [
      "Add header: X-Frame-Options: DENY (prevents all framing)",
      "Or: X-Frame-Options: SAMEORIGIN (allows same-origin framing only)",
      "Also add Content-Security-Policy: frame-ancestors 'none' for modern browsers",
    ],
    references: [
      { label: 'OWASP Clickjacking Defense Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html' },
      { label: 'CWE-1021: Improper Restriction of Rendered UI Layers', url: 'https://cwe.mitre.org/data/definitions/1021.html' },
    ],
    cvss: { score: 4.3, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'Required', scope: 'Unchanged', confidentiality: 'None', integrity: 'Low', availability: 'None' },
    vectraRiskScore: 42,
  },
  'vectra-missing-xcto': {
    category: 'Missing Security Header',
    summary: 'The X-Content-Type-Options header is absent. Without this header, browsers may perform MIME-type sniffing, potentially interpreting non-script responses as executable scripts. This can be exploited to execute malicious content uploaded as an innocuous file type.',
    businessImpact: [
      'MIME confusion attacks enabling script execution from uploaded files',
      'Bypass of content-type restrictions via browser sniffing behavior',
      'Increased XSS risk when serving user-uploaded content',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['X-Content-Type-Options header: not present in HTTP response'],
    remediation: [
      "Add header: X-Content-Type-Options: nosniff to all HTTP responses",
      "Ensure all responses include explicit, correct Content-Type headers",
    ],
    references: [
      { label: 'MDN X-Content-Type-Options', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options' },
      { label: 'CWE-430: Deployment of Wrong Handler', url: 'https://cwe.mitre.org/data/definitions/430.html' },
    ],
    cvss: { score: 3.1, attackVector: 'Network', attackComplexity: 'High', privilegesRequired: 'None', userInteraction: 'Required', scope: 'Unchanged', confidentiality: 'None', integrity: 'Low', availability: 'None' },
    vectraRiskScore: 22,
  },
  'vectra-missing-referrer-policy': {
    category: 'Missing Security Header',
    summary: 'The Referrer-Policy header is absent. Without this policy, full URL referrer information may be sent to third-party services when users navigate away from the application. This can leak sensitive URL parameters, session tokens, or internal path information.',
    businessImpact: [
      'URL-embedded sensitive data leaked to third-party services via Referer header',
      'Internal application path and parameter disclosure',
      'Privacy regulation compliance risk (GDPR)',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['Referrer-Policy header: not present in HTTP response'],
    remediation: [
      "Add header: Referrer-Policy: strict-origin-when-cross-origin",
      "Or: Referrer-Policy: no-referrer for maximum privacy",
      "Avoid sending sensitive data in URL parameters",
    ],
    references: [
      { label: 'MDN Referrer-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy' },
      { label: 'CWE-200: Exposure of Sensitive Information', url: 'https://cwe.mitre.org/data/definitions/200.html' },
    ],
    cvss: { score: 3.1, attackVector: 'Network', attackComplexity: 'High', privilegesRequired: 'None', userInteraction: 'Required', scope: 'Unchanged', confidentiality: 'Low', integrity: 'None', availability: 'None' },
    vectraRiskScore: 18,
  },
  'vectra-missing-permissions-policy': {
    category: 'Missing Security Header',
    summary: 'The Permissions-Policy (formerly Feature-Policy) header is absent. This header controls which browser features and APIs the application can use. Without it, embedded third-party content may gain access to powerful browser APIs such as camera, microphone, and geolocation.',
    businessImpact: [
      'Embedded content may access sensitive browser APIs (camera, microphone)',
      'Third-party scripts can request user location without restriction',
      'Reduced control over browser feature surface exposed to the application',
    ],
    affectedComponent: 'HTTP Response Headers',
    evidence: ['Permissions-Policy header: not present in HTTP response'],
    remediation: [
      "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
      "Restrict only features not actively required by your application",
      "Review the full list of controllable features at W3C Permissions Policy spec",
    ],
    references: [
      { label: 'MDN Permissions-Policy', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy' },
      { label: 'W3C Permissions Policy Specification', url: 'https://w3c.github.io/webappsec-permissions-policy/' },
    ],
    cvss: { score: 0.0, attackVector: 'Network', attackComplexity: 'Low', privilegesRequired: 'None', userInteraction: 'None', scope: 'Unchanged', confidentiality: 'None', integrity: 'None', availability: 'None' },
    vectraRiskScore: 7,
  },
}

function deriveVulnMeta(finding: FirestoreFinding): VulnMeta {
  const template = (finding.template ?? '').toLowerCase()
  const severity  = finding.severity ?? 'unknown'

  // Exact template lookup
  if (TEMPLATE_DB[template]) {
    const def  = TEMPLATE_DB[template]
    const base = DEFAULT_CVSS[severity] ?? DEFAULT_CVSS.unknown
    const cvss: CvssVector = { ...base, ...def.cvss }
    return {
      ...def,
      cvss,
      vectraRiskScore: def.vectraRiskScore ?? DEFAULT_RISK[severity] ?? 0,
    }
  }

  // Generic fallback — derive from description and severity
  const desc = finding.description ?? ''
  const base  = DEFAULT_CVSS[severity] ?? DEFAULT_CVSS.unknown

  return {
    category: severity === 'critical' ? 'Critical Vulnerability'
             : severity === 'high'     ? 'High Severity Vulnerability'
             : severity === 'medium'   ? 'Security Misconfiguration'
             : severity === 'low'      ? 'Low Severity Finding'
             : 'Informational Finding',
    summary: desc || `${finding.title} was detected on this asset. Review the technical details and apply the recommended remediation to reduce risk exposure.`,
    businessImpact: severity === 'critical' ? [
      'Potential for complete system compromise',
      'Unauthorized access to sensitive data',
      'Regulatory and compliance violations',
    ] : severity === 'high' ? [
      'Unauthorized access to application data or functions',
      'Potential for privilege escalation',
      'Increased attack surface exposure',
    ] : severity === 'medium' ? [
      'Information disclosure to unauthenticated parties',
      'Increased attacker reconnaissance capability',
    ] : [
      'Reduced defense-in-depth posture',
      'Minor information exposure',
    ],
    cvss: base,
    vectraRiskScore: DEFAULT_RISK[severity] ?? 0,
    affectedComponent: finding.host ?? finding.target ?? 'Web Application',
    evidence: [
      finding.matchedAt ? `Detected at: ${finding.matchedAt}` : '',
      desc ? `Detection: ${desc}` : '',
    ].filter(Boolean),
    remediation: [
      'Review the technical details of this finding with your security or development team.',
      'Apply vendor-recommended patches or configuration changes.',
      'Validate the remediation by re-scanning after changes are applied.',
    ],
    references: [
      { label: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/' },
    ],
  }
}

// ── UI Sub-components ─────────────────────────────────────────────────

function SectionHeader({ icon: Icon, title }: { icon: React.ComponentType<{ className?: string }>; title: string }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon className="w-3.5 h-3.5 text-muted-foreground" />
      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{title}</span>
    </div>
  )
}

function MetaRow({ label, value, mono = false, link = false }: { label: string; value: string; mono?: boolean; link?: boolean }) {
  return (
    <div className="flex items-start gap-3 py-1.5 border-b border-foreground/5 last:border-0">
      <span className="text-xs text-muted-foreground w-32 shrink-0 pt-0.5">{label}</span>
      <div className="flex-1 min-w-0">
        {link ? (
          <a
            href={value.startsWith('http') ? value : `https://${value}`}
            target="_blank" rel="noopener noreferrer"
            className={`text-xs text-primary hover:underline break-all flex items-center gap-1 ${mono ? 'font-mono' : ''}`}
          >
            {value}<ExternalLink className="w-3 h-3 shrink-0" />
          </a>
        ) : (
          <span className={`text-xs text-foreground break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
        )}
      </div>
    </div>
  )
}

function RiskMeter({ score }: { score: number }) {
  const pct   = Math.min(100, Math.max(0, score))
  const color = pct >= 80 ? 'bg-red-500' : pct >= 60 ? 'bg-orange-500' : pct >= 40 ? 'bg-yellow-500' : pct >= 20 ? 'bg-blue-400' : 'bg-gray-400'
  const label = pct >= 80 ? 'Critical Risk' : pct >= 60 ? 'High Risk' : pct >= 40 ? 'Medium Risk' : pct >= 20 ? 'Low Risk' : 'Informational'
  return (
    <div className="space-y-2">
      <div className="flex items-end justify-between">
        <span className="text-3xl font-bold text-foreground">{score}</span>
        <span className="text-xs text-muted-foreground mb-1">/ 100</span>
      </div>
      <div className="h-2 bg-foreground/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-semibold ${
        pct >= 80 ? 'text-red-500' : pct >= 60 ? 'text-orange-500' : pct >= 40 ? 'text-yellow-500' : pct >= 20 ? 'text-blue-400' : 'text-gray-400'
      }`}>{label}</span>
    </div>
  )
}

function CvssBar({ score }: { score: number }) {
  const pct   = (score / 10) * 100
  const color = score >= 9 ? 'bg-red-500' : score >= 7 ? 'bg-orange-500' : score >= 4 ? 'bg-yellow-500' : score > 0 ? 'bg-blue-400' : 'bg-gray-400'
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-2xl font-bold text-foreground">{score.toFixed(1)}</span>
        <span className="text-xs text-muted-foreground">/ 10.0</span>
      </div>
      <div className="h-1.5 bg-foreground/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

// ── Finding Drawer ────────────────────────────────────────────────────

function FindingDrawer({ finding, open, onClose }: { finding: FirestoreFinding | null; open: boolean; onClose: () => void }) {
  const [devMode, setDevMode] = useState(false)
  const [devClicks, setDevClicks] = useState(0)
  const [copied, setCopied] = useState(false)

  function handleDevTap() {
    const next = devClicks + 1
    setDevClicks(next)
    if (next >= 5) { setDevMode((v) => !v); setDevClicks(0) }
  }

  function copyReport() {
    if (!finding) return
    const meta  = deriveVulnMeta(finding)
    const lines = [
      `VULNERABILITY REPORT — ${finding.title}`,
      `${'='.repeat(60)}`,
      `Severity: ${finding.severity.toUpperCase()}`,
      `CVSS Score: ${meta.cvss.score.toFixed(1)} / 10.0`,
      `Vectra Risk Score: ${meta.vectraRiskScore} / 100`,
      `Discovery Source: ${finding.source ?? 'nuclei'}`,
      `Affected Host: ${finding.host ?? finding.target ?? '—'}`,
      `Affected URL: ${finding.matchedAt ?? '—'}`,
      `Detected: ${new Date(finding.createdAt).toLocaleString()}`,
      '',
      'EXECUTIVE SUMMARY',
      meta.summary,
      '',
      'BUSINESS IMPACT',
      ...meta.businessImpact.map((b) => `• ${b}`),
      '',
      'REMEDIATION',
      ...meta.remediation.map((r, i) => `${i + 1}. ${r}`),
      '',
      'REFERENCES',
      ...meta.references.map((r) => `• ${r.label}: ${r.url}`),
      '',
      `Generated by Vectra Security Platform`,
    ]
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.success('Report copied to clipboard')
  }

  if (!finding) return null

  const meta   = deriveVulnMeta(finding)
  const sevCls = SEVERITY_COLORS[finding.severity] ?? SEVERITY_COLORS.unknown
  const sourceLabel = finding.source === 'vectra' ? 'Vectra Checks' : finding.source === 'wpscan' ? 'WPScan' : 'Nuclei'
  const SourceIcon  = finding.source === 'vectra' ? ShieldCheck : finding.source === 'wpscan' ? Globe : Bug
  const sourceCls   = finding.source === 'vectra'
    ? 'bg-violet-500/10 text-violet-400 border-violet-500/20'
    : finding.source === 'wpscan'
    ? 'bg-green-500/10 text-green-400 border-green-500/20'
    : 'bg-blue-500/10 text-blue-400 border-blue-500/20'

  const cvssVector = [
    { label: 'Attack Vector',        value: meta.cvss.attackVector },
    { label: 'Attack Complexity',    value: meta.cvss.attackComplexity },
    { label: 'Privileges Required',  value: meta.cvss.privilegesRequired },
    { label: 'User Interaction',     value: meta.cvss.userInteraction },
    { label: 'Scope',                value: meta.cvss.scope },
    { label: 'Confidentiality',      value: meta.cvss.confidentiality },
    { label: 'Integrity',            value: meta.cvss.integrity },
    { label: 'Availability',         value: meta.cvss.availability },
  ]

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-full sm:w-[600px] bg-card border-foreground/10 flex flex-col p-0">

        {/* Header */}
        <SheetHeader className="px-6 pt-6 pb-4 border-b border-foreground/10 shrink-0">
          <div className="flex items-start gap-3">
            <span className={`text-xs font-semibold px-2.5 py-1 rounded border shrink-0 mt-0.5 uppercase ${sevCls}`}>
              {finding.severity}
            </span>
            <div className="flex-1 min-w-0">
              <SheetTitle className="text-base font-semibold text-foreground leading-snug">
                {finding.title}
              </SheetTitle>
              <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                <span className={`flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border ${sourceCls}`}>
                  <SourceIcon className="w-3 h-3" />{sourceLabel}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded border border-foreground/10 bg-foreground/5 text-muted-foreground">
                  {meta.category}
                </span>
              </div>
            </div>
          </div>
          <SheetDescription className="sr-only">Vulnerability report for {finding.title}</SheetDescription>
        </SheetHeader>

        <ScrollArea className="flex-1">
          <div className="px-6 py-5 space-y-7">

            {/* ── Section 1: Finding Overview ── */}
            <div>
              <SectionHeader icon={Shield} title="Finding Overview" />
              <div className="bg-foreground/3 border border-foreground/8 rounded-lg px-4 py-1">
                {finding.host && <MetaRow label="Affected Asset" value={finding.host} mono />}
                {finding.matchedAt && <MetaRow label="Affected URL" value={finding.matchedAt} mono link />}
                {!finding.matchedAt && !finding.host && finding.target && (
                  <MetaRow label="Scan Target" value={finding.target} mono link />
                )}
                <MetaRow label="Detection Source" value={sourceLabel} />
                <MetaRow
                  label="Detected"
                  value={new Date(finding.createdAt).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                />
                <MetaRow label="CVSS Score" value={`${meta.cvss.score.toFixed(1)} / 10.0`} />
                <MetaRow label="Vectra Risk" value={`${meta.vectraRiskScore} / 100`} />
              </div>
            </div>

            {/* ── Section 2: Executive Summary ── */}
            <div>
              <SectionHeader icon={FileText} title="Executive Summary" />
              <p className="text-sm text-foreground/85 leading-relaxed">{meta.summary}</p>
            </div>

            {/* ── Section 3: Business Impact ── */}
            <div>
              <SectionHeader icon={AlertTriangle} title="Business Impact" />
              <div className="space-y-2">
                {meta.businessImpact.map((item, i) => (
                  <div key={i} className="flex items-start gap-2.5">
                    <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${SEVERITY_BAR[finding.severity] ?? 'bg-gray-400'}`} />
                    <span className="text-sm text-foreground/80 leading-relaxed">{item}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Section 4: Technical Details ── */}
            <div>
              <SectionHeader icon={Target} title="Technical Details" />
              <div className="bg-foreground/3 border border-foreground/8 rounded-lg px-4 py-1">
                <MetaRow label="Affected Host" value={finding.host ?? finding.target ?? '—'} mono />
                {finding.matchedAt && <MetaRow label="Affected URL" value={finding.matchedAt} mono link />}
                <MetaRow label="Detection Method" value={sourceLabel} />
                <MetaRow label="Affected Component" value={meta.affectedComponent} />
              </div>

              {/* Proof of Detection */}
              {meta.evidence.length > 0 && (
                <div className="mt-3">
                  <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Proof of Detection</p>
                  <div className="bg-foreground/5 border border-foreground/10 rounded-lg p-3 space-y-1.5">
                    {meta.evidence.map((e, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <Eye className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
                        <span className="text-xs font-mono text-foreground/80">{e}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* ── Section 5: CVSS ── */}
            {meta.cvss.score > 0 && (
              <div>
                <SectionHeader icon={Shield} title="CVSS v3.1 Score" />
                <CvssBar score={meta.cvss.score} />
                <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-0 bg-foreground/3 border border-foreground/8 rounded-lg px-4 py-2">
                  {cvssVector.map(({ label, value }) => (
                    <div key={label} className="flex items-center justify-between py-1.5 border-b border-foreground/5 last:border-0">
                      <span className="text-[10px] text-muted-foreground">{label}</span>
                      <span className={`text-[10px] font-semibold ${
                        value === 'None' ? 'text-muted-foreground' :
                        value === 'Low'  ? 'text-blue-400' :
                        value === 'High' ? 'text-orange-400' :
                        value === 'Critical' ? 'text-red-400' :
                        'text-foreground'
                      }`}>{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Section 6: Vectra Risk Score ── */}
            <div>
              <SectionHeader icon={ShieldCheck} title="Vectra Risk Score" />
              <RiskMeter score={meta.vectraRiskScore} />
            </div>

            {/* ── Section 7: Remediation ── */}
            <div>
              <SectionHeader icon={Wrench} title="Remediation" />
              <div className="space-y-3">
                {meta.remediation.map((step, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <span className="w-5 h-5 rounded-full bg-primary/15 text-primary text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    <span className="text-sm text-foreground/80 leading-relaxed font-mono text-xs">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Section 8: References ── */}
            <div>
              <SectionHeader icon={BookOpen} title="References" />
              <div className="space-y-2">
                {meta.references.map((ref, i) => (
                  <a
                    key={i}
                    href={ref.url}
                    target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs text-primary hover:underline"
                  >
                    <ExternalLink className="w-3 h-3 shrink-0" />
                    {ref.label}
                  </a>
                ))}
              </div>
            </div>

            {/* ── Developer Mode ── (hidden behind 5-tap on version label) */}
            <div className="border-t border-foreground/5 pt-4">
              <button
                onClick={handleDevTap}
                className="text-[9px] text-foreground/15 hover:text-foreground/30 transition-colors select-none w-full text-left"
              >
                Vectra Security Platform — Internal
              </button>
              {devMode && (
                <div className="mt-3 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Developer Mode</span>
                    <button onClick={() => setDevMode(false)} className="text-[10px] text-muted-foreground hover:text-foreground">Close</button>
                  </div>
                  <pre className="bg-foreground/5 border border-foreground/10 rounded-lg p-3 text-[10px] font-mono text-foreground/70 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed max-h-64 overflow-y-auto">
                    {JSON.stringify(finding, null, 2)}
                  </pre>
                </div>
              )}
            </div>

          </div>
        </ScrollArea>

        {/* Footer actions */}
        <div className="px-6 py-4 border-t border-foreground/10 flex gap-2 shrink-0">
          {(finding.matchedAt || finding.host) && (
            <Button
              variant="outline" size="sm"
              className="rounded-lg border-foreground/20 gap-1.5 text-xs"
              onClick={() => {
                const url = finding.matchedAt || `https://${finding.host}`
                window.open(url, '_blank', 'noopener,noreferrer')
              }}
            >
              <Globe className="w-3.5 h-3.5" />View Asset
            </Button>
          )}
          <Button
            variant="outline" size="sm"
            className="flex-1 rounded-lg border-foreground/20 gap-1.5 text-xs"
            onClick={copyReport}
          >
            {copied ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
            Copy Report
          </Button>
          <Button
            variant="outline" size="sm"
            className="rounded-lg border-foreground/20 gap-1.5 text-xs"
            onClick={() => toast.info('Export feature coming soon')}
          >
            <FileText className="w-3.5 h-3.5" />Export
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────

export default function FindingsDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const router = useRouter()
  const { user } = useAuth()

  const [findings, setFindings] = useState<FirestoreFinding[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [selectedFinding, setSelectedFinding] = useState<FirestoreFinding | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  useEffect(() => {
    if (!user) return
    return listenToFindingsByScan(user.uid, scanId, (f) => {
      setFindings(f)
      setLoading(false)
    })
  }, [user, scanId])

  function openDrawer(finding: FirestoreFinding) {
    setSelectedFinding(finding)
    setDrawerOpen(true)
  }

  const target = findings[0]?.target ?? ''

  const counts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high:     findings.filter((f) => f.severity === 'high').length,
    medium:   findings.filter((f) => f.severity === 'medium').length,
    low:      findings.filter((f) => f.severity === 'low').length,
    info:     findings.filter((f) => f.severity === 'info').length,
  }

  const filtered = findings.filter((f) => {
    const matchSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      (f.description ?? '').toLowerCase().includes(search.toLowerCase()) ||
      (f.matchedAt ?? '').toLowerCase().includes(search.toLowerCase())
    const matchSev = severityFilter === 'all' || f.severity === severityFilter
    return matchSearch && matchSev
  })

  const sourceIcon = (source?: string) => {
    if (source === 'vectra')  return <ShieldCheck className="w-3 h-3" />
    if (source === 'wpscan')  return <Globe className="w-3 h-3" />
    return <Bug className="w-3 h-3" />
  }

  const sourceCls = (source?: string) =>
    source === 'vectra'  ? 'bg-violet-500/10 text-violet-400 border-violet-500/20' :
    source === 'wpscan'  ? 'bg-green-500/10 text-green-400 border-green-500/20' :
    'bg-blue-500/10 text-blue-400 border-blue-500/20'

  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-64">
        <div className="animate-spin rounded-full h-6 w-6 border border-primary border-t-transparent" />
      </div>
    )
  }

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-start gap-4">
        <Button variant="ghost" size="icon" onClick={() => router.push('/app/findings')} className="rounded-lg shrink-0">
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-bold text-foreground">Findings</h1>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
            {target && <p className="text-xs font-mono text-muted-foreground truncate">{target}</p>}
          </div>
        </div>
        <Button
          variant="outline" size="sm"
          className="rounded-lg border-foreground/20 shrink-0"
          onClick={() => router.push(`/app/scans/${scanId}`)}
        >
          View Scan →
        </Button>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
        {[
          { label: 'Critical', count: counts.critical, cls: 'text-red-500',    sev: 'critical' },
          { label: 'High',     count: counts.high,     cls: 'text-orange-500', sev: 'high' },
          { label: 'Medium',   count: counts.medium,   cls: 'text-yellow-500', sev: 'medium' },
          { label: 'Low',      count: counts.low,      cls: 'text-blue-400',   sev: 'low' },
          { label: 'Info',     count: counts.info,     cls: 'text-gray-400',   sev: 'info' },
        ].map((s) => (
          <button
            key={s.sev}
            onClick={() => setSeverityFilter(severityFilter === s.sev ? 'all' : s.sev)}
            className={`text-left p-3 rounded-lg border transition-colors ${
              severityFilter === s.sev ? 'border-foreground/30 bg-foreground/10' : 'border-foreground/10 bg-card hover:border-foreground/20'
            }`}
          >
            <div className={`text-xl font-bold ${s.cls}`}>{s.count}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Input
            placeholder="Search findings…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-foreground/5 border-foreground/20 rounded-lg"
          />
        </div>
        {severityFilter !== 'all' && (
          <Button variant="ghost" size="sm" onClick={() => setSeverityFilter('all')} className="rounded-lg text-muted-foreground">
            Clear filter ×
          </Button>
        )}
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} of {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Findings table */}
      {findings.length === 0 ? (
        <div className="text-center py-16 text-muted-foreground">
          <p className="text-sm">No findings for this scan yet.</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-muted-foreground">
          <p className="text-sm">No findings match your filters.</p>
        </div>
      ) : (
        <Card className="bg-card border-foreground/10">
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-foreground/10">
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Severity</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Source</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Vulnerability</th>
                    <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground">Affected URL</th>
                    <th className="py-3 px-4" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((finding) => (
                    <tr
                      key={finding.findingId}
                      className="border-b border-foreground/5 hover:bg-foreground/5 transition-colors cursor-pointer"
                      onClick={() => openDrawer(finding)}
                    >
                      <td className="py-3 px-4">
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded border uppercase ${SEVERITY_COLORS[finding.severity] ?? SEVERITY_COLORS.unknown}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`flex items-center gap-1 w-fit text-[10px] font-semibold px-2 py-0.5 rounded border ${sourceCls(finding.source)}`}>
                          {sourceIcon(finding.source)}
                          {finding.source === 'vectra' ? 'Vectra' : finding.source === 'wpscan' ? 'WPScan' : 'Nuclei'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-sm font-medium text-foreground max-w-[220px] truncate block">{finding.title}</span>
                        {finding.description && (
                          <span className="text-xs text-muted-foreground truncate block max-w-[220px]">{finding.description}</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs font-mono text-muted-foreground truncate block max-w-[200px]">
                          {finding.matchedAt ?? finding.host ?? '—'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Button
                          variant="ghost" size="sm"
                          className="h-7 rounded-lg text-primary hover:bg-primary/10 text-xs"
                          onClick={(e) => { e.stopPropagation(); openDrawer(finding) }}
                        >
                          Details →
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      <FindingDrawer finding={selectedFinding} open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  )
}
