import re 
from urllib.parse import urlparse 
import tldextract 
from bs4 import BeautifulSoup 
import logging 
from typing import Dict, Any 

from browser.privacy_detector import PrivacyDetector 

logger =logging.getLogger(__name__ )

class SecurityAnalyzer :
    """
    Worker-thread safe analysis engine for URLs and HTML pages.
    """

    #suspicious keywords often used in phishing/scam emails and domains
    SUSPICIOUS_KEYWORDS =[
    "login","verify","reset","urgent","update","secure",
    "account","bank","billing","support","confirm","free",
    "prize","lottery","winner","wallet","crypto","auth"
    ]

    #uRL Shorteners often masking phishing payload
    SHORTENERS =["bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","buff.ly","adf.ly"]

    #known legitimate brands for typosquatting checks
    KNOWN_BRANDS =["google","microsoft","facebook","apple","amazon","paypal","netflix"]

    #trusted domains that should always receive a SAFE verdict
    TRUSTED_DOMAINS =[
    "google.com","microsoft.com","apple.com","github.com",
    "amazon.com","facebook.com","youtube.com","wikipedia.org",
    "linkedin.com","twitter.com","x.com","netflix.com",
    "paypal.com","stackoverflow.com"
    ]

    @staticmethod 
    def analyze_url(url :str )->Dict[str, Any ]:
        """
        Analyze a URL for phishing characteristics.
        Returns a classification and an explanation.
        """
        if not url.startswith(('http://','https://')):
            url ='http://'+url 

        try :
            parsed =urlparse(url )
            ext =tldextract.extract(url )
        except Exception as e :
            return {
            "status":"DANGEROUS",
            "score":100 ,
            "reason":f"Malformed URL preventing accurate parsing: {e}"
            }

        domain =ext.domain 
        suffix =ext.suffix 
        subdomain =ext.subdomain 
        registered_domain =f"{domain}.{suffix}"if suffix else domain 

        #trusted Domain Whitelist — bypass scoring entirely
        if registered_domain.lower()in SecurityAnalyzer.TRUSTED_DOMAINS :
            return {
            "status":"SAFE",
            "score":0 ,
            "reason":f"Trusted domain({registered_domain}) — verified safe.",
            "flags":[f"Domain '{registered_domain}' is on the trusted whitelist."]
            }

        score =0 
        reasons =[]

        #1. IP Address instead of Domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",parsed.netloc.split(':')[0 ]):
            score +=50 
            reasons.append("URL uses an IP address instead of a domain name(High Risk).")

            #2. Protocol Check
        if parsed.scheme =="http":
            score +=20 
            reasons.append("Connection in use is HTTP, not secure HTTPS.")

            #3. URL Length
        if len(url )>75 :
            score +=15 
            reasons.append(f"URL is unusually long({len(url)} characters).")

            #4. Number of subdomains
        sub_count =len(subdomain.split('.'))if subdomain else 0 
        if sub_count >=3 :
            score +=20 
            reasons.append(f"URL has too many subdomains({sub_count}).")

            #5. Suspicious Keywords in URL
        for kw in SecurityAnalyzer.SUSPICIOUS_KEYWORDS :
            if kw in url.lower():
                score +=10 
                reasons.append(f"Contains suspicious manipulative keyword: '{kw}'.")

                #6. Typosquatting / Look-alike Domains
                #basic check for common brands(e.g. g00gle, rnicrosoft)
        for brand in SecurityAnalyzer.KNOWN_BRANDS :
            if brand in domain and domain !=brand :
                score +=30 
                reasons.append(f"Potential typosquatting of known brand '{brand}'.")
            elif domain.replace('0','o')==brand or domain.replace('rn','m')==brand :
                score +=50 
                reasons.append(f"High-confidence typosquatting detected masking as '{brand}'.")

                #7. Multiple dots / Special Chars / @ symbol
        if '@'in parsed.netloc :
            score +=40 
            reasons.append("URL contains '@' symbol, often used for credential spoofing.")
        if ext.domain.count('-')>2 :
            score +=15 
            reasons.append("Domain contains multiple hyphens, typical of disposable/scam networks.")

            #8. URL Shortener Masking
        if parsed.netloc.lower()in SecurityAnalyzer.SHORTENERS :
            score +=40 
            reasons.append(f"URL uses a known shortener({parsed.netloc}), which may mask malicious destinations.")

            #9. Suspicious TLDs
        risky_tlds =['xyz','tk','ml','ga','cf','gq','top','info','loan','club']
        if suffix in risky_tlds :
            score +=15 
            reasons.append(f"Uses a Top-Level Domain(.{suffix}) frequently associated with spam.")

            #classification thresholds — aligned with SAFE(0-40) / SUSPICIOUS(41-85) / DANGEROUS(86-100)
        if score >=86 :
            status ="DANGEROUS"
            final_reason ="URL exhibits highly dangerous patterns typical of phishing or malware distribution."
        elif score >=41 :
            status ="SUSPICIOUS"
            final_reason ="URL exhibits several suspicious traits. Proceed with caution."
        else :
            status ="SAFE"
            final_reason ="URL appears relatively safe, no major generic red flags detected."

        if not reasons :
            reasons.append("No immediate threats found via static analysis.")

        logger.debug(f"URL Analysis completed for {url} with score: {score}")

        return {
        "status":status ,
        "score":min(score, 100 ),
        "reason":final_reason ,
        "flags":reasons 
        }

    @staticmethod 
    def analyze_page(html_content :str, url :str )->Dict[str, Any ]:
        """
        Analyze the full HTML source to make a structured Security Report
        and calc a comprehensive Page Risk Score(0-100).
        """
        score =0 
        reasons =[]

        if not html_content :
            return {"status":"UNKNOWN","score":0 ,"reason":"No HTML content provided.","flags":[]}

        try :
            soup =BeautifulSoup(html_content ,"html.parser")
            text =soup.get_text().lower()
        except Exception as e :
            return {"status":"ERROR","score":0 ,"reason":f"HTML Parsing Error: {e}","flags":[]}

            #parse basic structural elements
        scripts =soup.find_all("script")
        links =soup.find_all("a",href =True )
        iframes =soup.find_all("iframe")
        forms =soup.find_all("form")

        #local counters for type safety
        hidden_iframes_count =0 
        password_forms_count =0 
        executables_linked_count =0 
        external_forms_detected =False 
        crypto_wallets_detected =False 
        brand_mismatch_detected =False 
        fake_login_suspect =False 

        report ={
        "url":url ,
        "domain":tldextract.extract(url ).domain ,
        "https_status":url.startswith("https://"),
        "total_links":len(links ),
        "total_scripts":len(scripts ),
        "hidden_iframes":0 ,
        "password_forms":0 ,
        "external_forms":False ,
        "executables_linked":0 ,
        "crypto_wallets":False ,
        "brand_mismatch":False ,
        "fake_login_suspect":False ,
        "score":0 ,
        "privacy_level":"UNKNOWN",
        "trackers":[]
        }

        #1. Base Score modifiers
        if not report["https_status"]:
            score +=15 
            reasons.append("Page loaded over insecure HTTP.")
            #2. Keyword / Phrase Scams
        scam_phrases =[
        ("urgent action required",20 ),
        ("verify your account",20 ),
        ("download attachment",15 ),
        ("claim your prize",25 ),
        ("your account is suspended",25 ),
        ("dear customer",10 ),
        ("password expired",20 ),
        ("unauthorized login attempt",15 )
        ]

        has_urgent_lang =False 
        for phrase, weight in scam_phrases :
            if phrase in text :
                has_urgent_lang =True 
                score +=weight 
                reasons.append(f"Contains manipulative urgency/scam phrase: '{phrase}'.")

                #3. Privacy & Trackers engine
        privacy_data =PrivacyDetector.detect_trackers(html_content )
        report["privacy_level"]=privacy_data["risk_level"]
        report["trackers"]=privacy_data["trackers"]

        if privacy_data["score_impact"]>0 :
            score +=privacy_data["score_impact"]
            if len(report["trackers"])>5 :
                score +=10 #high penalty for extreme tracking
                reasons.append(f"High volume of third-party tracking scripts({len(report['trackers'])} detected).")

                #4. Hidden elements / Base64 / Scripts
        if len(scripts )>30 :
            score +=10 
            reasons.append(f"Unusually high number of scripts loaded({len(scripts)}).")

        for script in scripts :
            script_text =script.string 
            if script_text and("atob("in script_text or "btoa("in script_text or "base64"in script_text.lower()):
                score +=15 
                reasons.append("Contains Base64 encoded scripts, common in injected obfuscated payloads.")
                break 

                #5. Credential Harvesting / Fake Login(Phishing Heuristics)
        for form in forms :
            action =form.get("action","").lower()
            password_inputs =form.find_all("input",{"type":"password"})
            text_inputs =form.find_all("input",{"type":["text","email"]})

            if password_inputs :
                password_forms_count +=1 

                if action and action.startswith("http://"):
                    score +=40 
                    reasons.append("Password form submits data over insecure HTTP.")

                try :
                    page_domain =tldextract.extract(url ).domain 
                    action_domain =tldextract.extract(action ).domain 
                    if action_domain and page_domain !=action_domain :
                        external_forms_detected =True 
                        score +=35 
                        reasons.append("Password form submits credentials to a mismatched external domain.")
                except Exception as e :
                    logging.debug(f"Failed to extract domains: {e}")

                    #fake Login / Phishing Aggregation Check
                is_brand_mismatch =any(b in text and b !=page_domain for b in SecurityAnalyzer.KNOWN_BRANDS )
                if is_brand_mismatch :
                    brand_mismatch_detected =True 

                if has_urgent_lang or external_forms_detected or is_brand_mismatch :
                    fake_login_suspect =True 
                    score +=50 
                    reasons.append("CRITICAL: High confidence Fake Login / Phishing Page detected. Do NOT enter credentials.")

                    #6. Input Traps(Hidden fields)
        hidden_inputs =soup.find_all("input",{"type":"hidden"})
        if len(hidden_inputs )>5 :
            score +=10 
            reasons.append(f"Unusually high number of hidden input fields({len(hidden_inputs)}).")

            #7. External I-Frames
        for iframe in iframes :
            src =iframe.get("src","")

            #check for explicitly styled hidden iframes(1x1 pixel or display:none)
            style =iframe.get("style","").replace(" ","").lower()
            if "display:none"in style or iframe.get("width")=="0"or iframe.get("width")=="1":
                hidden_iframes_count +=1 
                score +=15 
                reasons.append("Page contains invisible/hidden explicit iframes(potential exploit kit delivery).")

            if src :
                try :
                    if tldextract.extract(src ).domain !=tldextract.extract(url ).domain :
                        score +=5 
                        reasons.append("Page embeds external iframes(could be clickjacking or tracking).")
                except Exception as e :
                    logging.debug(f"Failed to extract iframe domain: {e}")

                    #8. Crypto Wallet Regex
        btc_pattern =r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{39,59}\b"
        eth_pattern =r"\b0x[a-fA-F0-9]{40}\b"

        if re.search(btc_pattern, text )or re.search(eth_pattern, text ):
            crypto_wallets_detected =True 
            score +=25 
            reasons.append("Page contains Cryptocurrency Wallet addresses, often found in extortion/investment scams.")

            #9. Suspicious Downloads
        for link in links :
            href =link.get('href','').lower()
            if href.endswith(('.exe','.bat','.scr','.vbs','.apk','.msi')):
                executables_linked_count +=1 

        if executables_linked_count >0 :
            score +=35 
            reasons.append(f"Page explicitly links to {executables_linked_count} dangerous executable files.")

            #10. Popup Triggers(JS)
        if "window.open"in text or "alert("in text :
            score +=5 
            reasons.append("Page contains explicit Javascript popup commands.")

            #11. Normalize Scoring & Classify(0-20 SAFE, 21-40 LOW, 41-60 MED, 61-80 HIGH, 81-100 DANGEROUS)
        final_score =min(max(int(score ),0 ),100 )

        report.update({
        "hidden_iframes":hidden_iframes_count ,
        "password_forms":password_forms_count ,
        "external_forms":external_forms_detected ,
        "executables_linked":executables_linked_count ,
        "crypto_wallets":crypto_wallets_detected ,
        "brand_mismatch":brand_mismatch_detected ,
        "fake_login_suspect":fake_login_suspect ,
        "score":final_score 
        })

        if final_score >=81 :
            status ="DANGEROUS"
            final_reason ="Page contains severe red flags indicative of credential harvesting or scam material."
        elif final_score >=61 :
            status ="HIGH"
            final_reason ="Page utilizes highly suspicious domains, forms, or executables."
        elif final_score >=41 :
            status ="MEDIUM"
            final_reason ="Page contains questionable elements(e.g., HTTP forms, tracking)."
        elif final_score >=21 :
            status ="LOW"
            final_reason ="Page is mostly safe but lacks best practices(e.g., HTTP over HTTPS)."
        else :
            status ="SAFE"
            final_reason ="Page appears structurally standard with no immediate malicious signatures found."

        if not reasons :
            reasons.append("No suspicious scripts, phrases, or forms identified.")

        logger.debug(f"HTML Analysis completed with score: {final_score}")

        report.update({
        "status":status ,
        "reason":final_reason ,
        "flags":list(set(reasons ))
        })
        return report 
