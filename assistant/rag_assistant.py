"""

RAG(Retrieval-Augmented Generation) Knowledge Engine.



adds a semantic search pipeline using Sentence Transformers and FAISS.

Enables natural language querying of the internal cybersecurity knowledge base

to provide context-aware assistance and remediation guidance.

"""

import json 

import logging 

from typing import List, Dict, Optional, Any 

import numpy as np 

try :

    from sentence_transformers import SentenceTransformer 

    import faiss 

    EMBEDDINGS_AVAILABLE =True 

except Exception :

#catches ImportError, OSError(WinError 1114 DLL failure in bundled exe),

#and any other loading failure. Falls back to keyword-matching mode

    EMBEDDINGS_AVAILABLE =False 



import config 



logger =logging.getLogger(__name__ )





class SecurityAssistant :

    """

    Orchestrates the retrieval and generation workflow for security queries.

    

    Attributes:

        embeddings_model(SentenceTransformer): Model for vectorizing text queries.

        faiss_index(faiss.Index): High-performance similarity search index.

        knowledge_base(List[Dict]): In-memory structured knowledge store.

    """



    def __init__(self ):

        """setup the semantic search engine and knowledge repository."""

        self.embeddings_model =None 

        self.faiss_index =None 

        self.knowledge_base =[]

        self._embeddings_status ="unavailable"

        self._faiss_status ="unavailable"

        self._initialize()



    def _initialize(self ):

        """

        Bootstrap the RAG pipeline.

        

        Loads the JSON knowledge base and attempts to setup the 

        vector search engine(FAISS) if dependencies are met.

        Falls back to keyword matching if ML libraries are unavailable.

        """

        #load knowledge base

        self._load_knowledge_base()



        #setup embeddings model(lightweight)

        if EMBEDDINGS_AVAILABLE :

            try :

                self.embeddings_model =SentenceTransformer(config.EMBEDDINGS_MODEL )

                self._embeddings_status ="loaded"

            except Exception as e :

                logger.warning("Could not load embeddings model: %s",e )

                self._embeddings_status =f"failed:{type(e).__name__}: {str(e)[:100]}"

                self.embeddings_model =None 



                #attempt FAISS index construction only if embeddings loaded

            if self.embeddings_model :

                try :

                    self._build_faiss_index()

                    self._faiss_status ="built"

                except Exception as e :

                    logger.warning("Could not build FAISS index: %s",e )

                    self._faiss_status =f"failed:{type(e).__name__}: {str(e)[:100]}"

        else :

            self._embeddings_status ="unavailable"

            self._faiss_status ="unavailable"

            logger.warning("Vector search dependencies missing. Operating in Safe Mode(Keyword Match).")



    def _load_knowledge_base(self ):

        """

        Load or hydrate the knowledge repository.

        

        Checks for existing knowledge artifacts; synthesizes a default 

        corpus if none exists(Cold Start).

        """

        if config.KNOWLEDGE_DOCS_PATH.exists():

            with open(config.KNOWLEDGE_DOCS_PATH ,'r',encoding ='utf-8')as f :

                self.knowledge_base =json.load(f )

        else :

        #create default knowledge base

            self.knowledge_base =self._create_default_knowledge_base()

            config.KNOWLEDGE_DOCS_PATH.parent.mkdir(exist_ok =True )

            with open(config.KNOWLEDGE_DOCS_PATH ,'w',encoding ='utf-8')as f :

                json.dump(self.knowledge_base, f ,indent =2 )



    def _create_default_knowledge_base(self )->List[Dict ]:

        """

        Synthesize comprehensive security knowledge corpus.

        

        Returns:

            List[Dict]: Extensive document set covering OWASP Top 10, MITRE ATT&CK, 

                       network security, cryptography, compliance, and more.

        """

        return[

        #=== SOCIAL ENGINEERING & PHISHING ===

        {

        "id":1 ,

        "topic":"Phishing Attacks",

        "content":"Phishing is a social engineering attack where attackers impersonate legitimate entities to steal sensitive information like credentials, credit cards, or personal data. Common indicators: suspicious sender addresses, urgent/threatening language, requests for credentials, poor grammar/spelling, mismatched URLs, unexpected attachments. Types include spear phishing(targeted), whaling(targeting executives), and vishing(voice phishing). Prevention: verify sender identity through separate channels, hover over links to check actual URLs, use 2FA/MFA, implement email filtering and SPF/DKIM/DMARC, conduct security awareness training, never click suspicious links or download unexpected attachments.",

        "category":"Social Engineering"

        },

        {

        "id":2 ,

        "topic":"Social Engineering Tactics",

        "content":"Social engineering manipulates people into divulging confidential information or performing actions that compromise security. Techniques include pretexting(creating false scenarios), baiting(offering something enticing), quid pro quo(promising benefits for information), tailgating(physical following), and impersonation. Attackers exploit trust, authority, urgency, and fear. Defense: verify identities independently, question unusual requests especially involving money or credentials, implement strict access controls, train employees to recognize manipulation tactics, establish verification procedures for sensitive requests, use challenge questions, and foster a security-conscious culture where questioning is encouraged.",

        "category":"Social Engineering"

        },



        #=== WEB APPLICATION SECURITY(OWASP) ===

        {

        "id":3 ,

        "topic":"SQL Injection(SQLi)",

        "content":"SQL Injection exploits vulnerabilities in database queries by inserting malicious SQL code through user inputs. Attackers can bypass authentication, extract sensitive data, modify/delete records, or execute administrative operations. Common in login forms, search boxes, and URL parameters. Detection: look for SQL error messages, unusual database queries, unexpected data access patterns. Prevention: use parameterized queries/prepared statements(NEVER concatenate user input), implement input validation and sanitization, apply least privilege to database accounts, use stored procedures, enable WAF(Web Application Firewall), perform regular code reviews and penetration testing, escape special characters, and implement proper error handling that doesn't reveal database structure.",

        "category":"OWASP Top 10"

        },

        {

        "id":4 ,

        "topic":"Cross-Site Scripting(XSS)",

        "content":"XSS allows attackers to inject malicious scripts(usually JavaScript) into web pages viewed by other users. Three types: Stored XSS(persistent, saved in database), Reflected XSS(immediate, via URL parameters), and DOM-based XSS(client-side). Impacts include session hijacking, credential theft, defacement, malware distribution. Prevention: validate and sanitize ALL user inputs, encode output data(HTML entity encoding), implement Content Security Policy(CSP) headers, use HTTPOnly and Secure flags on cookies, avoid innerHTML(use textContent), implement input length limits, use modern frameworks with built-in XSS protection(React, Angular), and conduct regular security testing.",

        "category":"OWASP Top 10"

        },

        {

        "id":5 ,

        "topic":"Cross-Site Request Forgery(CSRF)",

        "content":"CSRF tricks authenticated users into executing unwanted actions on web applications where they're logged in. Attacker crafts malicious requests that leverage the victim's active session. Common targets: fund transfers, email changes, password resets. Prevention: implement anti-CSRF tokens(synchronizer tokens), use SameSite cookie attribute, require re-authentication for sensitive actions, validate HTTP Referer header, use custom request headers for AJAX, implement CAPTCHA for critical operations, and educate users about staying logged out of sensitive sites when browsing.",

        "category":"OWASP Top 10"

        },

        {

        "id":6 ,

        "topic":"Broken Authentication",

        "content":"Broken authentication occurs when authentication mechanisms are implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens. Issues include weak password policies, credential stuffing, session fixation, exposed session IDs, lack of MFA. Prevention: implement multi-factor authentication(MFA), enforce strong password policies(length, complexity, no common passwords), use secure session management(random session IDs, timeout, regenerate after login), implement account lockout after failed attempts, use HTTPS for all authentication, hash passwords with strong algorithms(bcrypt, Argon2), never expose session IDs in URLs, implement CAPTCHA, and monitor for suspicious login patterns.",

        "category":"OWASP Top 10"

        },

        {

        "id":7 ,

        "topic":"Sensitive Data Exposure",

        "content":"Sensitive data exposure occurs when applications don't properly protect sensitive information like passwords, credit cards, health records, or personal data. Common causes: transmitting data in clear text, weak encryption, storing sensitive data unnecessarily, improper key management. Prevention: classify data by sensitivity, encrypt data at rest(AES-256) and in transit(TLS 1.2+), use strong encryption algorithms, implement proper key management(rotate keys, use HSM), don't store sensitive data unless necessary, mask/tokenize credit cards and PII, disable autocomplete on sensitive forms, implement secure deletion, and comply with regulations(GDPR, PCI-DSS, HIPAA).",

        "category":"OWASP Top 10"

        },

        {

        "id":8 ,

        "topic":"XML External Entity(XXE) Injection",

        "content":"XXE attacks exploit vulnerable XML processors that parse external entity references. Attackers can read local files, perform SSRF attacks, cause DoS, or execute remote code. Common in SOAP web services, file uploads, and API endpoints accepting XML. Prevention: disable XML external entity processing in all XML parsers, use less complex data formats like JSON when possible, implement input validation, update XML processors, use allow-lists for XML schemas, and implement proper error handling that doesn't reveal system information.",

        "category":"OWASP Top 10"

        },

        {

        "id":9 ,

        "topic":"Insecure Deserialization",

        "content":"Insecure deserialization occurs when untrusted data is used to abuse application logic, execute arbitrary code, or perform injection attacks. Common in Java, PHP, Python applications using serialization. Impacts include remote code execution, privilege escalation, and DoS. Prevention: avoid deserializing untrusted data, implement integrity checks(digital signatures), isolate deserialization in low-privilege environments, log deserialization exceptions and failures, restrict deserialization to specific classes(allow-listing), use simple data formats like JSON instead of native serialization, and monitor for deserialization activity.",

        "category":"OWASP Top 10"

        },

        {

        "id":10 ,

        "topic":"Security Misconfiguration",

        "content":"Security misconfiguration is the most common vulnerability, occurring when security settings are not properly defined, implemented, or maintained. Examples: default credentials, unnecessary features enabled, verbose error messages revealing system info, unpatched systems, insecure cloud storage. Prevention: implement secure configuration baselines, remove unnecessary features/services, change all default credentials, keep systems patched and updated, implement least privilege, use security headers(CSP, HSTS, X-Frame-Options), disable directory listing, implement proper error handling, use automated configuration scanning, and maintain security configuration documentation.",

        "category":"OWASP Top 10"

        },



        #=== auth & ACCESS CONTROL ===

        {

        "id":11 ,

        "topic":"Brute Force Attacks",

        "content":"Brute force attacks systematically try many password combinations to gain unauthorized access. Indicators: multiple failed login attempts from same IP, sequential login attempts, unusual login times/locations, dictionary word attempts. Types include credential stuffing(using leaked credentials), password spraying(trying common passwords across many accounts). Prevention: implement account lockout after N failed attempts, use progressive delays, require CAPTCHA after failures, enforce strong password policies, implement MFA, monitor and alert on suspicious login patterns, use rate limiting, implement IP blocking/geo-blocking, and educate users about password security.",

        "category":"Authentication"

        },

        {

        "id":12 ,

        "topic":"Multi-Factor Authentication(MFA)",

        "content":"MFA requires multiple verification factors: something you know(password), something you have(token, phone), something you are(biometric). Significantly reduces account compromise risk even if passwords are stolen. Types: SMS codes(least secure), authenticator apps(TOTP), hardware tokens(YubiKey), biometrics, push notifications. Best practices: use app-based or hardware MFA(avoid SMS), implement backup codes, require MFA for privileged accounts, use adaptive MFA based on risk, educate users about MFA fatigue attacks, and have account recovery procedures.",

        "category":"Authentication"

        },

        {

        "id":13 ,

        "topic":"Privilege Escalation",

        "content":"Privilege escalation occurs when attackers gain higher access levels than authorized. Vertical escalation: user to admin. Horizontal escalation: user to another user. Common techniques: exploiting misconfigurations, vulnerable software, weak permissions, sudo misuse, kernel exploits. Detection: monitor sudo usage, admin account access, unusual permission changes, new privileged accounts, scheduled task modifications. Prevention: principle of least privilege, regular access reviews, patch systems promptly, use separate admin accounts, implement PAM(Privileged Access Management), monitor privileged operations, disable unnecessary services, and use application allow-listing.",

        "category":"MITRE ATT&CK"

        },

        {

        "id":14 ,

        "topic":"Password Security Best Practices",

        "content":"Strong passwords are critical for security. Requirements: minimum 12-16 characters, mix of uppercase, lowercase, numbers, symbols, no dictionary words, no personal information, unique per account. Use passphrases(4+ random words) for memorability. Never reuse passwords across sites. Prevention: use password managers(1Password, Bitwarden, LastPass), enable MFA everywhere possible, check if passwords were breached(haveibeenpwned.com), change passwords if breach suspected, avoid password hints, don't share passwords, use password generators, and implement password expiration for sensitive accounts.",

        "category":"Authentication"

        },



        #=== NETWORK SECURITY ===

        {

        "id":15 ,

        "topic":"Man-in-the-Middle(MITM) Attacks",

        "content":"MITM attacks intercept communication between two parties, allowing attackers to eavesdrop or modify data. Common on public WiFi, compromised routers, or through ARP spoofing, DNS spoofing, SSL stripping. Attackers can steal credentials, session tokens, sensitive data. Prevention: use HTTPS/TLS for all communications, verify SSL certificates, avoid public WiFi for sensitive operations, use VPN on untrusted networks, implement certificate pinning in apps, use HSTS headers, enable DNSSEC, monitor for certificate anomalies, and educate users about secure browsing.",

        "category":"Network Security"

        },

        {

        "id":16 ,

        "topic":"Denial of Service(DoS) and DDoS",

        "content":"DoS attacks overwhelm systems to make them unavailable to legitimate users. DDoS uses multiple sources(botnets). Types: volumetric(bandwidth exhaustion), protocol(SYN floods), application layer(HTTP floods). Impacts: service downtime, revenue loss, reputation damage. Prevention: implement rate limiting, use traffic filtering and scrubbing, deploy CDN and load balancers, use DDoS protection services(Cloudflare, Akamai), implement connection limits, use SYN cookies, monitor traffic patterns, have incident response plan, use anycast routing, and maintain excess capacity.",

        "category":"Availability"

        },

        {

        "id":17 ,

        "topic":"Port Scanning and Network Reconnaissance",

        "content":"Port scanning identifies open ports and services on target systems, often the first step in attacks. Tools: nmap, masscan. Techniques: TCP connect, SYN scan, UDP scan, version detection. Detection: monitor for unusual connection patterns, multiple connection attempts, sequential port access. Prevention: close unnecessary ports, use firewalls to restrict access, implement IDS/IPS, use port knocking, disable unnecessary services, implement network segmentation, monitor firewall logs, and use honeypots to detect reconnaissance.",

        "category":"Network Security"

        },

        {

        "id":18 ,

        "topic":"Firewall Configuration and Best Practices",

        "content":"Firewalls control network traffic based on security rules. Types: packet filtering, stateful inspection, application layer, next-gen(NGFW). Best practices: default deny(allow-list approach), segment networks(DMZ, internal, management), use both network and host firewalls, log all denied traffic, regularly review rules, remove unused rules, document all changes, implement egress filtering, use geo-blocking where appropriate, enable IPS features, and conduct regular firewall audits.",

        "category":"Network Security"

        },

        {

        "id":19 ,

        "topic":"VPN Security and Remote Access",

        "content":"VPNs create encrypted tunnels for secure remote access. Protocols: OpenVPN(most secure), WireGuard(modern, fast), IPSec, L2TP. Security considerations: use strong encryption(AES-256), implement MFA for VPN access, use certificate-based authentication, enable kill switch, avoid free VPNs(privacy concerns), keep VPN software updated, use split tunneling carefully, implement VPN access logging, restrict VPN access by role, and monitor for unusual VPN usage patterns.",

        "category":"Network Security"

        },

        {

        "id":20 ,

        "topic":"Network Segmentation and Zero Trust",

        "content":"Network segmentation divides networks into isolated zones to limit lateral movement. Zero Trust assumes no implicit trust, verifying every access request. Implementation: use VLANs, separate critical systems, implement micro-segmentation, use software-defined networking, enforce least privilege access, require authentication for all resources, implement continuous verification, monitor all traffic, use identity-aware proxies, and apply defense in depth. Benefits: contain breaches, reduce attack surface, improve compliance, and enable granular access control.",

        "category":"Network Security"

        },



        #=== MALWARE & THREATS ===

        {

        "id":21 ,

        "topic":"Ransomware Attacks and Response",

        "content":"Ransomware encrypts victim data and demands payment for decryption. Common variants: WannaCry, Ryuk, REvil, LockBit. Delivery: phishing emails, RDP exploitation, software vulnerabilities. Prevention: maintain offline backups(3-2-1 rule), patch systems promptly, use email filtering, implement application allow-listing, disable macros, train users, use EDR solutions, segment networks. If infected: isolate infected systems immediately, don't pay ransom(no guarantee), report to authorities, restore from backups, analyze attack vector, and improve defenses.",

        "category":"Malware"

        },

        {

        "id":22 ,

        "topic":"Trojan Horses and Backdoors",

        "content":"Trojans disguise malicious code as legitimate software. Types: backdoor trojans(remote access), banking trojans(steal financial data), downloader trojans(install more malware), RATs(Remote Access Trojans). Common delivery: fake software, email attachments, drive-by downloads. Detection: unusual network traffic, unexpected processes, new services, registry changes. Prevention: download software only from official sources, verify digital signatures, use antivirus/EDR, implement application control, monitor outbound connections, keep software updated, and use sandboxing for unknown files.",

        "category":"Malware"

        },

        {

        "id":23 ,

        "topic":"Spyware and Keyloggers",

        "content":"Spyware secretly monitors user activity and collects information. Keyloggers record keystrokes to steal passwords and sensitive data. Types: software keyloggers, hardware keyloggers, screen capture tools. Indicators: slow performance, unexpected network activity, new browser toolbars, changed settings. Prevention: use antivirus/anti-spyware, avoid downloading from untrusted sources, keep software updated, use virtual keyboards for sensitive inputs, implement application allow-listing, monitor for suspicious processes, use EDR solutions, and physically secure devices.",

        "category":"Malware"

        },

        {

        "id":24 ,

        "topic":"Rootkits and Persistent Threats",

        "content":"Rootkits hide malicious activity by modifying the operating system. Types: user-mode, kernel-mode, bootkit, firmware rootkits. Extremely difficult to detect and remove. Indicators: hidden processes/files, disabled security tools, unusual system behavior. Detection: use rootkit scanners(GMER, TDSSKiller), boot from clean media, check integrity of system files, monitor for kernel modifications. Prevention: keep systems patched, use secure boot, implement UEFI protection, use TPM, avoid running as administrator, use EDR with behavioral analysis, and maintain clean system images for comparison.",

        "category":"Malware"

        },

        {

        "id":25 ,

        "topic":"Advanced Persistent Threats(APT)",

        "content":"APTs are prolonged, targeted attacks by sophisticated adversaries(often nation-states). Characteristics: stealthy, persistent, well-resourced, multi-stage, custom malware. Phases: reconnaissance, initial compromise, establish foothold, escalate privileges, lateral movement, data exfiltration, maintain presence. Defense: implement defense in depth, use threat intelligence, deploy EDR/XDR, monitor for anomalies, segment networks, use deception technology(honeypots), conduct threat hunting, implement zero trust, maintain incident response capability, and assume breach mentality.",

        "category":"Threats"

        },



        #=== CRYPTOGRAPHY ===

        {

        "id":26 ,

        "topic":"Encryption Fundamentals",

        "content":"Encryption protects data confidentiality by converting plaintext to ciphertext. Symmetric encryption(AES, ChaCha20): same key for encryption/decryption, fast, used for bulk data. Asymmetric encryption(RSA, ECC): public/private key pairs, slower, used for key exchange and digital signatures. Best practices: use AES-256 for symmetric, RSA-2048+ or ECC for asymmetric, use authenticated encryption(GCM mode), implement proper key management, use TLS 1.2+ for transport, avoid deprecated algorithms(DES, MD5, SHA-1), use strong random number generation, and implement key rotation.",

        "category":"Cryptography"

        },

        {

        "id":27 ,

        "topic":"TLS/SSL and HTTPS Security",

        "content":"TLS(Transport Layer Security) encrypts data in transit between client and server. HTTPS is HTTP over TLS. Best practices: use TLS 1.2 minimum(prefer TLS 1.3), disable older protocols(SSL 2.0, 3.0, TLS 1.0, 1.1), use strong cipher suites, implement HSTS(HTTP Strict Transport Security), use valid certificates from trusted CAs, implement certificate pinning in apps, enable OCSP stapling, use forward secrecy, monitor certificate expiration, and implement CAA DNS records.",

        "category":"Cryptography"

        },

        {

        "id":28 ,

        "topic":"Digital Signatures and PKI",

        "content":"Digital signatures provide authentication, integrity, and non-repudiation using asymmetric cryptography. PKI(Public Key Infrastructure) manages digital certificates. Components: Certificate Authority(CA), Registration Authority, certificate repository, revocation lists(CRL/OCSP). Use cases: code signing, email signing(S/MIME), document signing, SSL/TLS certificates. Best practices: protect private keys(use HSM), verify certificate chains, check revocation status, use appropriate key sizes, implement certificate lifecycle management, and maintain offline root CAs.",

        "category":"Cryptography"

        },



        #=== INCIDENT RESPONSE & FORENSICS ===

        {

        "id":29 ,

        "topic":"Incident Response Process",

        "content":"Incident response handles security breaches systematically. Phases: 1) Preparation(plans, tools, training), 2) Detection and Analysis(identify incident, assess scope), 3) Containment(short-term: isolate, long-term: patches), 4) Eradication(remove threat), 5) Recovery(restore systems), 6) Post-Incident(lessons learned, improve defenses). Best practices: maintain incident response plan, establish CSIRT team, define roles/responsibilities, practice with tabletop exercises, maintain communication channels, document everything, preserve evidence, and conduct post-mortems.",

        "category":"Incident Response"

        },

        {

        "id":30 ,

        "topic":"Digital Forensics and Evidence Collection",

        "content":"Digital forensics investigates security incidents and collects evidence. Principles: maintain chain of custody, preserve original evidence, document everything, use write blockers, create forensic images. Analysis areas: file system, memory, network traffic, logs, registry. Tools: EnCase, FTK, Autopsy, Volatility, Wireshark. Process: identify evidence sources, preserve volatile data(memory), create forensic copies, analyze artifacts, document findings, and present results. Legal considerations: admissibility, proper handling, expert testimony.",

        "category":"Forensics"

        },

        {

        "id":31 ,

        "topic":"Log Management and SIEM",

        "content":"Security Information and Event Management(SIEM) aggregates and analyzes logs from multiple sources. Capabilities: log collection, normalization, correlation, alerting, dashboards, compliance reporting. Use cases: detect anomalies, investigate incidents, meet compliance, threat hunting. Best practices: collect logs from all critical systems, use centralized logging, implement log retention policies, protect log integrity, use correlation rules, tune alerts to reduce false positives, integrate threat intelligence, and conduct regular log reviews.",

        "category":"Monitoring"

        },



        #=== COMPLIANCE & GOVERNANCE ===

        {

        "id":32 ,

        "topic":"GDPR Compliance",

        "content":"General Data Protection Regulation(GDPR) protects EU citizens' personal data. Key requirements: lawful basis for processing, data minimization, purpose limitation, consent management, right to access/erasure/portability, data breach notification(72 hours), privacy by design, DPO appointment, DPIA for high-risk processing. Penalties: up to 4% of global revenue or €20M. Compliance: map data flows, implement privacy controls, maintain records of processing, conduct DPIAs, establish breach response procedures, train staff, and implement technical measures(encryption, pseudonymization).",

        "category":"Compliance"

        },

        {

        "id":33 ,

        "topic":"PCI-DSS Requirements",

        "content":"Payment Card Industry Data Security Standard(PCI-DSS) protects cardholder data. 12 requirements across 6 goals: 1) Secure network(firewalls, no default passwords), 2) Protect cardholder data(encryption, truncation), 3) Vulnerability management(antivirus, secure code), 4) Access control(need-to-know, unique IDs, physical security), 5) Monitor networks(logging, monitoring), 6) Security policy. Compliance levels based on transaction volume. Requirements: never store CVV, encrypt transmission, maintain secure systems, restrict access, and conduct regular testing.",

        "category":"Compliance"

        },

        {

        "id":34 ,

        "topic":"Security Frameworks(NIST, ISO 27001)",

        "content":"Security frameworks provide structured approaches to cybersecurity. NIST Cybersecurity Framework: Identify, Protect, Detect, Respond, Recover. ISO 27001: international standard for ISMS(Information Security Management System), includes risk assessment, controls, continuous improvement. Benefits: systematic approach, demonstrate due diligence, improve security posture, meet compliance requirements. Implementation: conduct gap analysis, define scope, assess risks, select controls, implement policies/procedures, train staff, monitor effectiveness, and pursue certification.",

        "category":"Governance"

        },



        #=== CLOUD SECURITY ===

        {

        "id":35 ,

        "topic":"Cloud Security Best Practices",

        "content":"Cloud security requires shared responsibility between provider and customer. Key areas: identity and access management(use IAM roles, MFA, least privilege), data protection(encrypt at rest and in transit, use KMS), network security(security groups, NACLs, VPC), monitoring(CloudTrail, CloudWatch, GuardDuty), compliance(understand certifications), configuration management(avoid public S3 buckets, disable unused services). Best practices: use infrastructure as code, implement CSPM tools, enable logging, conduct regular audits, use cloud-native security services, and implement backup/DR.",

        "category":"Cloud Security"

        },

        {

        "id":36 ,

        "topic":"Container and Kubernetes Security",

        "content":"Container security addresses unique risks in containerized environments. Concerns: vulnerable images, insecure configurations, runtime threats, orchestration security. Best practices: scan images for vulnerabilities, use minimal base images, don't run as root, use read-only file systems, implement network policies, use secrets management, enable RBAC, implement pod security policies, use admission controllers, monitor runtime behavior, keep Kubernetes updated, and use service mesh for encryption.",

        "category":"Cloud Security"

        },



        #=== SECURE DEVELOPMENT ===

        {

        "id":37 ,

        "topic":"Secure Coding Practices",

        "content":"Secure coding prevents vulnerabilities during development. Principles: validate all inputs, encode outputs, use parameterized queries, implement proper authentication/authorization, handle errors securely, use secure libraries, avoid hardcoded secrets, implement least privilege, use security headers, enable logging. OWASP Secure Coding Practices: input validation, output encoding, authentication/password management, session management, access control, cryptographic practices, error handling, data protection, communication security, and system configuration.",

        "category":"Development"

        },

        {

        "id":38 ,

        "topic":"DevSecOps and Security Testing",

        "content":"DevSecOps integrates security into DevOps pipelines. Practices: shift left(early security testing), automate security testing, use SAST(static analysis), DAST(dynamic analysis), SCA(software composition analysis), implement security gates, conduct code reviews, use dependency scanning, implement secrets scanning, perform penetration testing, use infrastructure as code scanning, and maintain security champions. Tools: SonarQube, Snyk, OWASP ZAP, Burp Suite, GitGuardian. Goal: find and fix vulnerabilities early when cheaper to remediate.",

        "category":"Development"

        },



        #=== EMERGING THREATS ===

        {

        "id":39 ,

        "topic":"Zero-Day Vulnerabilities",

        "content":"Zero-day exploits target unknown vulnerabilities before patches are available. Characteristics: no known fix, high value to attackers, often used in targeted attacks. Defense strategies: defense in depth(multiple security layers), network segmentation(limit blast radius), intrusion detection(behavioral analysis), application allow-listing, rapid patch management, virtual patching(WAF rules), threat intelligence, and assume breach mentality. Mitigation: isolate affected systems, implement compensating controls, monitor for exploitation indicators, and apply patches immediately when available.",

        "category":"Vulnerabilities"

        },

        {

        "id":40 ,

        "topic":"Supply Chain Attacks",

        "content":"Supply chain attacks compromise trusted vendors or software to reach targets. Examples: SolarWinds, Kaseya, NotPetya. Attack vectors: compromised software updates, malicious dependencies, hardware implants, compromised credentials. Prevention: vet third-party vendors, implement vendor risk management, use software composition analysis, verify digital signatures, implement network segmentation, monitor for anomalies, use zero trust architecture, maintain software bill of materials(SBOM), and implement least privilege for third-party access.",

        "category":"Threats"

        },



        #=== MOBILE & IOT SECURITY ===

        {

        "id":41 ,

        "topic":"Mobile Device Security",

        "content":"Mobile security addresses smartphones and tablets. Threats: malicious apps, phishing, insecure WiFi, lost/stolen devices, OS vulnerabilities. Best practices: enable device encryption, use strong passcodes/biometrics, enable remote wipe, keep OS updated, download apps only from official stores, review app permissions, avoid public WiFi or use VPN, enable find my device, implement MDM for corporate devices, use containerization for work data, and educate users about mobile threats.",

        "category":"Mobile Security"

        },

        {

        "id":42 ,

        "topic":"IoT Security Challenges",

        "content":"IoT devices present unique security challenges: limited resources, long lifecycles, weak authentication, lack of updates, insecure defaults. Common issues: default credentials, unencrypted communications, vulnerable firmware, lack of physical security. Attacks: Mirai botnet, camera hijacking, smart home exploitation. Security measures: change default credentials, segment IoT networks, disable unnecessary features, implement network monitoring, use strong authentication, encrypt communications, keep firmware updated, conduct security assessments, and consider security in procurement.",

        "category":"IoT Security"

        },



        #=== SECURITY OPERATIONS ===

        {

        "id":43 ,

        "topic":"Vulnerability Management",

        "content":"Vulnerability management identifies, evaluates, and remediates security weaknesses. Process: 1) Discovery(asset inventory, scanning), 2) Assessment(vulnerability scanning, penetration testing), 3) Prioritization(CVSS scoring, risk-based), 4) Remediation(patching, configuration changes, compensating controls), 5) Verification(rescan, validation). Best practices: maintain asset inventory, scan regularly, prioritize based on risk and exploitability, establish SLAs for patching, use automated tools, track metrics, and integrate with change management.",

        "category":"Operations"

        },

        {

        "id":44 ,

        "topic":"Penetration Testing",

        "content":"Penetration testing simulates real attacks to identify vulnerabilities. Types: black box(no knowledge), white box(full knowledge), gray box(partial knowledge). Phases: reconnaissance, scanning, exploitation, maintaining access, reporting. Scope: network, web applications, wireless, physical, social engineering. Methodologies: OWASP Testing Guide, PTES, OSSTMM. Best practices: define clear scope and rules of engagement, obtain written authorization, use qualified testers, test in isolated environments when possible, document findings with evidence, provide remediation guidance, and retest after fixes.",

        "category":"Testing"

        },

        {

        "id":45 ,

        "topic":"Threat Intelligence",

        "content":"Threat intelligence provides actionable information about threats. Types: strategic(trends, risk), tactical(TTPs), operational(campaigns), technical(IoCs). Sources: open source(OSINT), commercial feeds, ISACs, government, internal telemetry. Use cases: proactive defense, incident response, risk assessment, security awareness. Implementation: define requirements, collect from multiple sources, analyze and enrich, disseminate to stakeholders, integrate with security tools(SIEM, firewall, IDS), and measure effectiveness. Frameworks: MITRE ATT&CK, Diamond Model, Cyber Kill Chain.",

        "category":"Intelligence"

        },



        #=== BUSINESS CONTINUITY ===

        {

        "id":46 ,

        "topic":"Backup and Disaster Recovery",

        "content":"Backup and DR ensure business continuity after incidents. 3-2-1 rule: 3 copies of data, 2 different media types, 1 offsite copy. Backup types: full, incremental, differential. DR metrics: RTO(Recovery Time Objective), RPO(Recovery Point Objective). Best practices: automate backups, test restores regularly, encrypt backups, store offsite/offline(ransomware protection), document procedures, maintain DR plan, conduct DR drills, use immutable backups, implement versioning, and monitor backup success.",

        "category":"Business Continuity"

        },

        {

        "id":47 ,

        "topic":"Security Awareness Training",

        "content":"Security awareness training educates users about cybersecurity threats and best practices. Topics: phishing recognition, password security, social engineering, physical security, data handling, incident reporting, mobile security, acceptable use. Delivery: onboarding training, annual refreshers, phishing simulations, newsletters, posters, lunch-and-learns. Best practices: make training engaging and relevant, use real-world examples, conduct simulated attacks, measure effectiveness, provide immediate feedback, reward good behavior, make reporting easy, and foster security culture.",

        "category":"Awareness"

        },



        #=== ADVANCED TOPICS ===

        {

        "id":48 ,

        "topic":"Artificial Intelligence in Cybersecurity",

        "content":"AI enhances cybersecurity through automation and pattern recognition. Applications: anomaly detection, threat hunting, malware analysis, UEBA(User and Entity Behavior Analytics), automated response, phishing detection, vulnerability assessment. Benefits: process vast data, identify subtle patterns, reduce false positives, enable proactive defense. Challenges: adversarial AI, false positives, explainability, data quality requirements. Best practices: combine AI with human expertise, validate AI decisions, use diverse training data, monitor for bias, and maintain human oversight for critical decisions.",

        "category":"Advanced"

        },

        {

        "id":49 ,

        "topic":"Blockchain Security",

        "content":"Blockchain provides distributed, immutable ledgers but has unique security considerations. Threats: 51% attacks, smart contract vulnerabilities, private key theft, exchange hacks, consensus attacks. Smart contract risks: reentrancy, integer overflow, access control issues. Security measures: secure key management(hardware wallets, multi-sig), audit smart contracts, use established frameworks, implement proper access controls, monitor for anomalies, use reputable exchanges, enable 2FA, and understand consensus mechanism security properties.",

        "category":"Advanced"

        },

        {

        "id":50 ,

        "topic":"Quantum Computing and Post-Quantum Cryptography",

        "content":"Quantum computers threaten current cryptography. Shor's algorithm can break RSA and ECC. Harvest now, decrypt later attacks collect encrypted data for future decryption. Post-quantum cryptography develops quantum-resistant algorithms. NIST standardization: lattice-based, hash-based, code-based, multivariate cryptography. Preparation: inventory cryptographic assets, plan migration strategy, implement crypto-agility, monitor NIST standards, test post-quantum algorithms, and prioritize long-term sensitive data protection.",

        "category":"Advanced"

        }

        ]



    def _build_faiss_index(self ):

        """

        build vector search index.

        

        Encodes all knowledge base documents into high-dimensional vectors

        and indexes them using L2 distance(Euclidean) for fast similarity search.

        """

        if not self.embeddings_model or not self.knowledge_base :

            return 



        try :

        #make embeddings

            texts =[doc['content']for doc in self.knowledge_base ]

            embeddings =self.embeddings_model.encode(texts, show_progress_bar =False )



            #create FAISS index

            dimension =embeddings.shape[1 ]

            self.faiss_index =faiss.IndexFlatL2(dimension )

            self.faiss_index.add(embeddings.astype('float32'))



            #persist index for faster subsequent loads

            faiss.write_index(self.faiss_index, str(config.FAISS_INDEX_PATH ))



        except Exception as e :

            logger.warning("Could not build FAISS index: %s",e )

            self.faiss_index =None 



    def query(self, question :str, max_results :int =None )->Dict[str, Any ]:

        """

        runs a natural language query with intent detection and RAG.

        

        Args:

            question: User query string.

            max_results: Max number of documents to get.

            

        Returns:

            Dict: Query context, answer, and references.

        """

        max_results =max_results or config.MAX_RAG_RESULTS 



        try :

        #1. Intent Detection

            intent =self._detect_intent(question )



            #2. Conversational Handler

            if intent !='cybersecurity':

                answer =self._get_conversational_response(intent, question )

                return {

                'question':question ,

                'answer':answer ,

                'sources':[],

                'success':True 

                }



                #3. RAG Pipeline

            relevant_docs =self._retrieve_documents(question, max_results )

            response =self._generate_response(question, relevant_docs )



            #4. Related Topics Suggestions

            if relevant_docs :

                response +=self._generate_related_topics(relevant_docs )



            return {

            'question':question ,

            'answer':response ,

            'sources':relevant_docs ,

            'success':True 

            }



        except Exception as e :

            return {

            'question':question ,

            'answer':f'Error processing query: {str(e)}',

            'diagnostics':{

            'embeddings':self._embeddings_status ,

            'faiss':self._faiss_status ,

            'error_type':type(e ).__name__ ,

            },

            'sources':[],

            'success':False 

            }



    def _retrieve_documents(self, query :str, k :int )->List[Dict ]:

        """

        Strategy Selection: Semantic Search vs Keyword Fallback.

        

        Prefers vector search(FAISS) for semantic understanding.

        Falls back to keyword matching if ML components are offline.

        """

        if self.embeddings_model and self.faiss_index :

            return self._retrieve_with_faiss(query, k )

        else :

            return self._retrieve_with_keywords(query, k )



    def _detect_intent(self, question :str )->str :

        """Lightweight intent detection for conversation handling."""

        q =question.lower().strip()

        if not q :

            return 'empty'



        q_clean ="".join(c for c in q if c.isalnum()or c.isspace())

        words =q_clean.split()



        if not words :

            return 'empty'



        if any(w in words for w in['thanks','thx'])or 'thank you'in q :

            return 'thanks'



        if 'how are you'in q or "how're you"in q or "how do you do"in q :

            return 'status'



        if any(phrase in q for phrase in['who are you','what are you','what is this','your name']):

            return 'identity'



        if any(phrase in q for phrase in['what can you do','what can you',

        'can you help','help me']):

            return 'general'



        greeting_words =['hi','hello','hey','greetings','howdy']

        if any(w in words for w in greeting_words )and len(words )<=4 :

            return 'greeting'



        return 'cybersecurity'



    def _get_conversational_response(self, intent :str, question :str )->str :

        """make characterful responses based on conversation intent."""

        if intent =='greeting':

            return("Hello! 👋 I'm your AI Security Assistant. I can help you understand threats, "

            "best practices, and security concepts. What would you like to know?")

        elif intent =='status':

            return("I'm functioning perfectly and my security algorithms are optimized! "

            "Ready to help you tackle any cybersecurity challenges. What can I assist you with today?")

        elif intent =='identity':

            return("I'm a virtual AI assistant within the Cybersecurity Companion. "

            "I am intentionally trained on an extensive cybersecurity knowledge base covering "

            "OWASP Top 10, Network Security, Malware analysis, and Compliance protocols. "

            "I'm here to answer your security questions and help you learn.")

        elif intent =='thanks':

            return "You're very welcome! Feel free to ask if you have any more cybersecurity questions. Stay safe! 😊"

        elif intent =='empty':

            return "I didn't quite catch that. Could you please specify a cybersecurity topic or question?"

        elif intent =='general':

            return("I can help you with a wide range of cybersecurity topics!\n\n"

            "**Ask Questions:**\n"

            "• *What is phishing?*\n"

            "• *How to prevent SQL injection?*\n\n"

            "**Get Guidance:**\n"

            "• *Best practices for password security*\n"

            "• *Difference between XSS and CSRF*\n\n"

            "I'm specifically focused on cybersecurity. Ask me anything!")



        return "I'm here to help with cybersecurity questions."



    def _generate_related_topics(self, docs :List[Dict ])->str :

        """Extract related topics from the knowledge base retrieval results."""

        if len(docs )<=1 :

            return ""



        main_topic =docs[0 ].get('topic','')

        topics =[doc['topic']for doc in docs[1 :6 ]if 'topic'in doc and doc['topic']!=main_topic ]

        unique_topics =list(dict.fromkeys(topics ))



        if not unique_topics :

            return ""



        suggestion ="\n\n**Would you like to learn more about related topics such as:**\n"

        for t in unique_topics[:5 ]:

            suggestion +=f"• *{t}*\n"



        return suggestion 





    def _retrieve_with_faiss(self, query :str, k :int )->List[Dict ]:

        """

        runs semantic similarity search using dense vector embeddings.

        """

        try :

        #encode query

            query_embedding =self.embeddings_model.encode([query ],show_progress_bar =False )



            #search

            distances, indices =self.faiss_index.search(query_embedding.astype('float32'),k )



            #resolve indices to documents

            results =[]

            for idx in indices[0 ]:

                if idx <len(self.knowledge_base ):

                    results.append(self.knowledge_base[idx ])



            return results 



        except Exception :

        #fallback on critical failure

            return self._retrieve_with_keywords(query, k )



    def _retrieve_with_keywords(self, query :str, k :int )->List[Dict ]:

        """

        Fallback Retrieval: Simple token overlap matching.

        """

        query_lower =query.lower()

        scored_docs =[]



        for doc in self.knowledge_base :

            score =0 

            content_lower =doc['content'].lower()

            topic_lower =doc['topic'].lower()



            #simple keyword matching weighting

            for word in query_lower.split():

                if len(word )>3 :#skip stop words/noise

                    if word in topic_lower :

                        score +=3 #higher weight for topic match

                    if word in content_lower :

                        score +=1 



            if score >0 :

                scored_docs.append((score, doc ))



                #sort by relevance score

        scored_docs.sort(reverse =True, key =lambda x :x[0 ])

        return[doc for _, doc in scored_docs[:k ]]



    def _generate_response(self, question :str, relevant_docs :List[Dict ])->str :

        """

        Synthesize an intelligent, contextual response from retrieved knowledge.

        

         analyzes the question intent and make smart responses

        that directly address what the user is asking, regardless of phrasing.

        """

        if not relevant_docs :

            return self._generate_no_results_response(question )



            #analyze question intent

        question_lower =question.lower()

        intent =self._analyze_question_intent(question_lower )



        #make response based on intent and available knowledge

        if intent =='what_is':

            return self._generate_definition_response(relevant_docs, question_lower )

        elif intent =='how_to':

            return self._generate_howto_response(relevant_docs, question_lower )

        elif intent =='why':

            return self._generate_explanation_response(relevant_docs, question_lower )

        elif intent =='prevention':

            return self._generate_prevention_response(relevant_docs, question_lower )

        elif intent =='detection':

            return self._generate_detection_response(relevant_docs, question_lower )

        elif intent =='comparison':

            return self._generate_comparison_response(relevant_docs, question_lower )

        else :

            return self._generate_comprehensive_response(relevant_docs, question_lower )



    def _analyze_question_intent(self, question :str )->str :

        """Determine what the user is really asking for."""

        #what is / Define

        if any(phrase in question for phrase in['what is','what are','define','explain','tell me about']):

            return 'what_is'



            #how to / Steps

        if any(phrase in question for phrase in['how to','how do i','how can i','steps to','way to']):

            return 'how_to'



            #why / Reasoning

        if any(phrase in question for phrase in['why','reason','purpose of']):

            return 'why'



            #prevention / Protection

        if any(phrase in question for phrase in['prevent','protect','secure','defend','stop','avoid','mitigate']):

            return 'prevention'



            #detection / Identification

        if any(phrase in question for phrase in['detect','identify','recognize','spot','find','discover','signs of']):

            return 'detection'



            #comparison / Difference

        if any(phrase in question for phrase in['difference','compare','versus','vs','better than']):

            return 'comparison'



        return 'general'



    def _generate_definition_response(self, docs :List[Dict ],question :str )->str :

        """make a clear definition/explanation response."""

        main_doc =docs[0 ]

        response =[f"**{main_doc['topic']}**\n"]



        #extract the core definition(usually first 1-2 sentences)

        content =main_doc['content']

        sentences =content.split('. ')



        #provide concise definition

        definition ='. '.join(sentences[:2 ])+'.'

        response.append(definition )



        #add key characteristics if available

        if 'types:'in content.lower()or 'characteristics:'in content.lower():

            response.append(f"\n{content}")

        else :

        #extract key points

            response.append(f"\n**Key Points:**")

            response.append(content )



        return '\n'.join(response )



    def _generate_howto_response(self, docs :List[Dict ],question :str )->str :

        """make step-by-step or procedural guidance."""

        main_doc =docs[0 ]

        response =[f"**How to Address: {main_doc['topic']}**\n"]



        content =main_doc['content']



        #extract prevention/mitigation steps

        if 'prevention:'in content.lower():

            parts =content.split('Prevention:')

            response.append(parts[0 ].strip())

            response.append("\n**Steps to Prevent/Mitigate:**")

            response.append(parts[1 ].strip())

        elif 'best practices:'in content.lower():

            parts =content.split('Best practices:')

            response.append(parts[0 ].strip())

            response.append("\n**Best Practices:**")

            response.append(parts[1 ].strip())

        else :

            response.append(content )



        return '\n'.join(response )



    def _generate_prevention_response(self, docs :List[Dict ],question :str )->str :

        """Focus on prevention and protection measures."""

        response =["**Prevention and Protection Measures**\n"]



        #collect all prevention strategies from relevant docs

        prevention_strategies =[]

        for doc in docs[:3 ]:#use top 3 most relevant

            content =doc['content']

            if 'prevention:'in content.lower():

                prev_text =content.split('Prevention:')[-1 ].split('.')[0 :3 ]

                strategies ='. '.join(prev_text )

                prevention_strategies.append(f"**{doc['topic']}:**\n{strategies}")

            elif 'best practices:'in content.lower():

                bp_text =content.split('Best practices:')[-1 ].split('.')[0 :3 ]

                strategies ='. '.join(bp_text )

                prevention_strategies.append(f"**{doc['topic']}:**\n{strategies}")



        if prevention_strategies :

            response.extend(prevention_strategies )

        else :

        #fallback to full content of main doc

            response.append(docs[0 ]['content'])



        return '\n\n'.join(response )



    def _generate_detection_response(self, docs :List[Dict ],question :str )->str :

        """Focus on detection and identification."""

        response =["**Detection and Identification**\n"]



        #extract detection-related information

        for doc in docs[:2 ]:

            content =doc['content']

            response.append(f"**{doc['topic']}:**")



            if 'detection:'in content.lower():

                det_text =content.split('Detection:')[-1 ].split('Prevention:')[0 ]

                response.append(det_text.strip())

            elif 'indicators:'in content.lower()or 'indicators include'in content.lower():

            #extract indicators section

                if 'Indicators:'in content :

                    ind_text =content.split('Indicators:')[-1 ].split('.')[0 :3 ]

                else :

                    ind_text =content.split('indicators include')[-1 ].split('.')[0 :3 ]

                response.append("Indicators: "+'. '.join(ind_text ))

            else :

            #show first part of content

                response.append(content.split('.')[0 :2 ][0 ]+'.')



            response.append("")#blank line



        return '\n'.join(response )



    def _generate_explanation_response(self, docs :List[Dict ],question :str )->str :

        """Explain the 'why' behind something."""

        main_doc =docs[0 ]

        response =[f"**Understanding {main_doc['topic']}**\n"]



        #provide context and reasoning

        content =main_doc['content']

        sentences =content.split('. ')



        #give comprehensive explanation

        response.append('. '.join(sentences[:4 ])+'.')



        return '\n'.join(response )



    def _generate_comparison_response(self, docs :List[Dict ],question :str )->str :

        """Compare multiple concepts."""

        if len(docs )<2 :

            return self._generate_comprehensive_response(docs, question )



        response =["**Comparison**\n"]



        for i, doc in enumerate(docs[:3 ],1 ):

            response.append(f"**{i}. {doc['topic']}:**")

            #show first 2 sentences

            sentences =doc['content'].split('. ')

            response.append('. '.join(sentences[:2 ])+'.')

            response.append("")



        return '\n'.join(response )



    def _generate_comprehensive_response(self, docs :List[Dict ],question :str )->str :

        """make a comprehensive response for general questions."""

        main_doc =docs[0 ]

        response =[f"**{main_doc['topic']}**\n"]

        response.append(main_doc['content'])



        return '\n'.join(response )



    def _generate_no_results_response(self, question :str )->str :

        """make helpful response when no relevant docs found."""

        suggestions =[

        "I don't have specific information about that in my knowledge base.",

        "\n\n**I can help you with topics like:**",

        "• Web Application Security(SQL Injection, XSS, CSRF)",

        "• Network Security(Firewalls, VPNs, MITM attacks)",

        "• Malware and Threats(Ransomware, Trojans, APTs)",

        "• Authentication(MFA, Password Security, Brute Force)",

        "• Cryptography(Encryption, TLS/SSL, Digital Signatures)",

        "• Cloud Security and Container Security",

        "• Compliance(GDPR, PCI-DSS, ISO 27001)",

        "• Incident Response and Forensics",

        "• And many more cybersecurity topics!",

        "\n\nTry asking about a specific security threat, attack type, or protection measure."

        ]

        return '\n'.join(suggestions )



    def get_threat_explanation(self, threat_type :str )->str :

        """get canonical definition and remediation for a specific threat."""

        result =self.query(threat_type, max_results =1 )

        return result['answer']

