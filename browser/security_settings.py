import json 
import os 
import logging 
from PyQt6.QtCore import QObject, QUrl 
from PyQt6.QtWebEngineCore import(QWebEngineProfile, QWebEngineSettings, 
QWebEngineUrlRequestInterceptor, 
QWebEngineUrlRequestInfo )

import config 
from browser.privacy_detector import PrivacyDetector 

logger =logging.getLogger(__name__ )

class SecurityInterceptor(QWebEngineUrlRequestInterceptor ):
    def __init__(self, settings_manager, parent =None ):
        super().__init__(parent )
        self.sm =settings_manager 

    def interceptRequest(self, info :QWebEngineUrlRequestInfo ):
        url =info.requestUrl().toString()

        #hTTPS Enforcement(Redirect HTTP to HTTPS)
        if self.sm.get("strict_https")and url.startswith("http://"):
            sec_url =url.replace("http://","https://",1 )
            info.redirect(QUrl(sec_url ))
            logger.debug(f"Intercepted HTTP request and redirected to HTTPS: {sec_url}")
            return 

            #tracker Blocking Drop logic
        if self.sm.get("block_trackers"):
        #check domain against known tracker patterns
            for _tracker_brand, patterns in PrivacyDetector.KNOWN_TRACKERS.items():
                for pat in patterns :
                    _fmt =pat.replace("\\.",".").replace(".*","")#extract rough domain chunks
                    if _fmt in url :
                        info.block(True )
                        logger.debug(f"Blocked Tracking Domain Injection: {url}")
                        return 


class SecuritySettingsManager(QObject ):
    """
    Manages browser profile settings and writes custom preferences to an external JSON.
    """

    DEFAULTS ={
    "block_js":False ,
    "block_popups":True ,
    "disable_plugins":True ,
    "disable_local_storage":False ,
    "block_third_party_cookies":True ,
    "disable_screen_capture":True ,
    "block_auto_downloads":True ,
    "strict_https":True ,
    "block_trackers":True 
    }

    def __init__(self, profile :QWebEngineProfile, conf_path :str ):
        super().__init__()
        self.profile =profile 
        self.conf_path =conf_path 
        self.settings_cache =self.DEFAULTS.copy()

        #attach interceptor
        self.interceptor =SecurityInterceptor(self )
        self.profile.setUrlRequestInterceptor(self.interceptor )

        self.load_settings()

    def get(self, key ):
        return self.settings_cache.get(key, self.DEFAULTS.get(key ))

    def set(self, key, val ):
        self.settings_cache[key ]=val 
        self.apply_to_profile()
        self.save_settings()

    def load_settings(self ):
        if os.path.exists(self.conf_path ):
            try :
                with open(self.conf_path ,"r",encoding ="utf-8")as f :
                    data =json.load(f )
                    for k in self.settings_cache :
                        if k in data :
                            self.settings_cache[k ]=data[k ]
                logger.info("Loaded custom Security Settings.")
            except Exception as e :
                logger.error(f"Failed to load security config: {e}")
        self.apply_to_profile()

    def save_settings(self ):
        dirname =os.path.dirname(self.conf_path )
        if dirname :
            os.makedirs(dirname, exist_ok =True )
        try :
            with open(self.conf_path ,"w",encoding ="utf-8")as f :
                json.dump(self.settings_cache, f ,indent =4 )
        except Exception as e :
            logger.error(f"Failed to save security config: {e}")

    def apply_to_profile(self ):
        """Immediately bind all QWebEngine internal boolean keys from config."""
        s =self.profile.settings()

        #webEngine Setting Enums Mapping
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, not self.get("block_js"))
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, not self.get("block_popups"))
        s.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, not self.get("disable_plugins"))
        s.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, not self.get("disable_local_storage"))
        s.setAttribute(QWebEngineSettings.WebAttribute.ScreenCaptureEnabled, not self.get("disable_screen_capture"))

        #enforce cookies block policy
        policy =QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies if self.get("block_third_party_cookies")else QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies 
        self.profile.setPersistentCookiesPolicy(policy )

        logger.debug(f"Profile Security Settings Synced: {self.settings_cache}")

    def determine_shield_level(self )->str :
        """Returns Standard, Hardened, or Paranoid based on config complexity."""
        score =0 
        if self.get("block_js"):score +=3 
        if self.get("disable_local_storage"):score +=2 
        if self.get("block_third_party_cookies"):score +=1 
        if self.get("block_trackers"):score +=1 
        if self.get("strict_https"):score +=1 

        if score >=5 :return "Paranoid"
        if score >=2 :return "Hardened"
        return "Standard"
