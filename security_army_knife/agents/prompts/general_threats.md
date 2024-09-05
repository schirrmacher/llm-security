# Threats

- In the following some threats are presented which might affect the target system.
- You must also create new threats if applicable.

## Authentication Threats

- For authentication protocols consider missing validation of roles and permissions
- Make sure that each participant in a system can only access the data which she should have access to
- If OAuth/OpenID with JWT is applied, make sure to validate the claims in every stage of critical operations
- Apply the least privilege principle
- For all authentication threats consider e2e tests as mitigation which are testing the unhappy path (invalid authentication attempt)

## Missing DDoS Protection

- If services are not served via Tyk there is a chance that those are vulnerable to DDoS attacks.
- There must be a WAF and DoS protection mechanism to prevent attacks on availability.
- This only affects public endpoints, accessible through the public internet.

## Missing Security Monitoring

- For operating secure products we rely on security monitoring.
- Teams know their product best, so they must come up with edge cases and scenarios which might harm our customers.
- Define potential threats given the architecture, be creative!

## Mobile Application Threats

- For mobile applications, like Android or iOS, consider the following threats
- You must not mention the threats if they do not affect the described system below
- Challenge if sensitive key material is stored in secure enclaves
- Challenge if APIs offer proper bot protection to prevent automated attacks
- Only list the above when you identify mobile app technologies (iOS, Android etc.)!

## Software Dependency Threats

- Consider security issues in third-party components
- Consider information stealer malware in dependencies and challenge firewall setups
- Mitigation is to run CVE scans, like Trivy, Renovate, GCP Artifact Analysis

## Browser Related Threats

- The must only consider the threats when you are really sure that browser based technologies (JavaScript, HTML, Angular, React etc.) are applied in the system below!
- Consider proper settings of the same-origin policy (SOP) for Cross-origin resource sharing (CORS)
- Consider proper sanitization to prevent Cross-Site Scripting (XSS) attacks
- Consider the threat of Cross-Site Request Forgery (CSRF)
- Consider Server-Side Request Forgery Attacks (SSRF) which exploits flaws in web applications to access internal resources

# References

- Add this for monitoring and alerting related mitigations: https://paymenttools.atlassian.net/wiki/spaces/ARCH/pages/1570963461/Security+Guide
- Add this for authentication related mitigations: https://paymenttools.atlassian.net/wiki/spaces/ARCH/pages/1323663361/DRAFT+Authentication+Authorization+Guide
