import re 
import logging 
from typing import Dict, Any, List 
from bs4 import BeautifulSoup 

class PrivacyDetector :
    """
    Worker-thread safe privacy and tracker detection engine for HTML pages.
    Identifies common analytics scripts, pixels, and fingerprinting tools.
    """

    KNOWN_TRACKERS ={
    "Google Analytics":[r"google-analytics\.com/analytics\.js",r"googletagmanager\.com/gtag/js"],
    "Facebook Pixel":[r"connect\.facebook\.net/.*/fbevents\.js"],
    "DoubleClick":[r"doubleclick\.net"],
    "Hotjar":[r"static\.hotjar\.com/c/hotjar-"],
    "Mixpanel":[r"cdn\.mxpnl\.com/libs/mixpanel"],
    "Segment":[r"cdn\.segment\.com/analytics\.js"],
    "Twitter Ads":[r"static\.ads-twitter\.com/uwt\.js"],
    "LinkedIn Insights":[r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js"],
    "TikTok Pixel":[r"analytics\.tiktok\.com/i18n/pixel"],
    "Pinterest Tag":[r"s\.pinimg\.com/ct/core\.js"]
    }

    @staticmethod 
    def detect_trackers(html_content :str )->Dict[str, Any ]:
        """
        Scan page HTML for known tracking scripts.
        """
        found_trackers =[]
        score_impact =0 

        if not html_content :
            return {"risk_level":"UNKNOWN","score_impact":0 ,"trackers":[]}

        try :
            soup =BeautifulSoup(html_content ,"html.parser")
            scripts =soup.find_all("script")

            #combine all script content and sources into a single large block for regex
            script_sources =[]
            for s in scripts :
                src =s.get("src","")
                content =s.string or ""
                script_sources.append(src )
                script_sources.append(content )

            combined_script_data ="\\n".join(script_sources ).lower()

            for tracker_name, signatures in PrivacyDetector.KNOWN_TRACKERS.items():
                for sig in signatures :
                    if re.search(sig, combined_script_data ):
                        found_trackers.append(tracker_name )
                        score_impact +=2 
                        break #only count each tracker brand once

        except Exception as e :
            logging.debug(f"Privacy detection parsing warning: {e}")
            pass 

            #determine Privacy Risk
        if len(found_trackers )>5 :
            risk_level ="HIGH"
        elif len(found_trackers )>0 :
            risk_level ="MEDIUM"
        else :
            risk_level ="LOW"

        return {
        "risk_level":risk_level ,
        "score_impact":min(score_impact, 20 ),
        "trackers":found_trackers 
        }
