import os 
import pathlib 
import markdown 
from datetime import datetime 
from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLineEdit, 
QPushButton, QSplitter, QFrame, QTextBrowser, 
QLabel, QProgressBar, QScrollArea, QSizePolicy )
from PyQt6.QtCore import Qt, QUrl, QThreadPool, QSizeF, QMarginsF, QTimer 
from PyQt6.QtGui import QFont, QIcon, QColor, QTextCursor, QTextDocument, QPageSize, QPageLayout, QPdfWriter 
import PyQt6.QtWebEngineCore 
from PyQt6.QtWebEngineWidgets import QWebEngineView 

import config 
from utils.workers import Worker 
from ui.animations import fade_in 
from browser.security_analyzer import SecurityAnalyzer 
from browser.tools import SecurityTools 
from browser.download_protection import DownloadProtector 
from browser.report_generator import ReportGenerator 
from browser.security_settings import SecuritySettingsManager 
from ui.advanced_security_panel import AdvancedSecurityPanel 


class BrowserTab(QWidget ):
    """
    Integrated Secure Browser with AI Security Analysis Panel on the right.
    """
    def __init__(self, parent ):
        super().__init__()
        self.parent =parent 
        self._is_analyzing =False 
        self._active_worker_count =0 #simple counter; QRunnable is not hashable so a set() crashes
        self._export_token =__import__('secrets').token_hex(32 )#cryptographic signature for exports

        #determine paths
        self.base_dir =pathlib.Path(__file__ ).parent.parent 
        self.homepage_url =QUrl.fromLocalFile(str(self.base_dir /"assets"/"browser_home.html"))

        #tools dispatcher map for AI
        self.tool_map ={
        "ssl":self._run_ssl_tool ,
        "ip":self._run_ip_tool ,
        "headers":self._run_headers_tool ,
        "securityheaders":self._run_headers_tool ,
        "hash":self._run_hash_tool ,
        "base64e":lambda text :f"Encoded:\n```text\n{SecurityTools.base64_encode(text)}\n```",
        "base64d":lambda text :f"Decoded:\n```text\n{SecurityTools.base64_decode(text)}\n```",
        "whois":self._run_whois_tool ,
        "dns":self._run_dns_tool ,
        "password":self._run_password_tool ,
        "links":self._trigger_links_tool ,
        "cookies":self._trigger_cookies_tool ,
        "risk":self._trigger_page_analysis 
        }
        self.latest_scan_data =None 

        self.init_ui()
        self._load_homepage()

    def init_ui(self ):
        """Build the split layout(Browser + AI Panel)."""
        main_layout =QHBoxLayout(self )
        main_layout.setContentsMargins(0, 0 ,0, 0 )
        main_layout.setSpacing(0 )

        self.splitter =QSplitter(Qt.Orientation.Horizontal )

        #==========================================
        #lEFT SIDE: BROWSER VIEW
        #==========================================
        self.browser_container =QWidget()
        browser_layout =QVBoxLayout(self.browser_container )
        browser_layout.setContentsMargins(0, 0 ,0, 0 )
        browser_layout.setSpacing(0 )

        #1. Navigation Bar
        self.nav_bar =QWidget()
        self.nav_bar.setObjectName("browserNavBar")
        self.nav_bar.setStyleSheet(f"""
            QWidget#browserNavBar {{
                background-color: {config.COLOR_SURFACE};
                border-bottom: 1px solid {config.COLOR_BORDER};
                padding: 5px;
            }}
        """)
        nav_layout =QHBoxLayout(self.nav_bar )
        nav_layout.setContentsMargins(10, 8 ,10, 8 )
        nav_layout.setSpacing(10 )

        #buttons
        self.btn_back =QPushButton("◀")
        self.btn_forward =QPushButton("▶")
        self.btn_reload =QPushButton("↻")
        self.btn_home =QPushButton("🏠")

        for btn in[self.btn_back, self.btn_forward, self.btn_reload, self.btn_home ]:
            btn.setFixedSize(36, 36 )
            btn.setCursor(Qt.CursorShape.PointingHandCursor )
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #0078D4;
                    border: none;
                    border-radius: 18px;
                    color: #fFFFFF;
                    font-size: 16px;
                    font-weight: bold;
                    font-family: "Segoe UI", "Segoe UI Emoji", "Segoe UI Symbol", "Arial", sans-serif;
                }
                QPushButton:hover {
                    background-color: #005A9E;
                }
                QPushButton:pressed {
                    background-color: #004578;
                }
            """)

        self.btn_back.clicked.connect(self._nav_back )
        self.btn_forward.clicked.connect(self._nav_forward )
        self.btn_reload.clicked.connect(self._nav_reload )
        self.btn_home.clicked.connect(self._load_homepage )

        #uRL Bar
        self.url_bar =QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL or execute search...")
        self.url_bar.setStyleSheet(f"""
            QLineEdit {{
                background-color: {config.COLOR_BACKGROUND};
                border: 1px solid {config.COLOR_BORDER};
                border-radius: 18px;
                padding: 8px 15px;
                font-family: {config.FONT_FAMILY};
                font-size: 13px;
                color: {config.COLOR_TEXT};
            }}
            QLineEdit:focus {{
                border: 1px solid {config.COLOR_PRIMARY};
            }}
        """)
        self.url_bar.returnPressed.connect(self._navigate_entered_url )

        #advanced Security Control Shield Logic
        self.btn_security_shield =QPushButton("🔒 Controls")
        self.btn_security_shield.setCursor(Qt.CursorShape.PointingHandCursor )
        self.btn_security_shield.setFixedHeight(34 )
        self._update_shield_btnUI()
        self.btn_security_shield.clicked.connect(self._open_advanced_security_panel )

        self.btn_security_shield.clicked.connect(self._open_advanced_security_panel )

        #download Manager(Permission Based)
        from PyQt6.QtWidgets import QToolButton 
        self.btn_download =QToolButton()
        self.btn_download.setText("No Downloads")
        self.btn_download.setFixedSize(120, 32 )
        self.btn_download.setCursor(Qt.CursorShape.PointingHandCursor )
        self.btn_download.setStyleSheet(f"""
            QToolButton {{
                background-color: transparent; border: 1px solid #808080;
                border-radius: 0px; color: #808080; font-size: 11px; padding: 0 10px;
            }}
        """)
        self.btn_download.clicked.connect(self._toggle_download_drawer )

        nav_layout.addWidget(self.btn_back )
        nav_layout.addWidget(self.btn_forward )
        nav_layout.addWidget(self.btn_reload )
        nav_layout.addWidget(self.btn_home )
        nav_layout.addWidget(self.btn_download )
        nav_layout.addWidget(self.url_bar, 1 )#stretchable
        nav_layout.addWidget(self.btn_security_shield )

        #download Drawer(Floating UI)
        self.download_drawer =QFrame(self.browser_container )
        self.download_drawer.setGeometry(150, 45, 260, 300 )
        self.download_drawer.setStyleSheet("background-color: #ffffff; border: 1px solid #ccc; box-shadow: none !important; border-radius: 5px;")
        self.drawer_layout =QVBoxLayout(self.download_drawer )
        self.drawer_layout.setAlignment(Qt.AlignmentFlag.AlignTop )
        self.download_drawer.hide()

        #2. QtWebEngineView Core
        self.web_view =QWebEngineView()
        self.web_view.loadFinished.connect(self._on_load_finished )
        self.web_view.urlChanged.connect(self._update_urlbar_on_change )

        #security Policy Bootstrapper
        conf_path =os.path.join(self.base_dir ,"config","security_config.json")
        self.sm =SecuritySettingsManager(self.web_view.page().profile(),conf_path )

        #download Protection Interception
        self.web_view.page().profile().downloadRequested.connect(self._handle_download )

        #loading bar attached below nav
        self.loading_bar =QProgressBar()
        self.loading_bar.setFixedHeight(3 )
        self.loading_bar.setTextVisible(False )
        self.loading_bar.setRange(0, 100 )
        self.loading_bar.setValue(0 )
        self.loading_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                background-color: transparent;
            }}
            QProgressBar::chunk {{
                background-color: {config.COLOR_PRIMARY};
            }}
        """)
        self.web_view.loadProgress.connect(self._update_loading_progress )

        browser_layout.addWidget(self.nav_bar )
        browser_layout.addWidget(self.loading_bar )
        browser_layout.addWidget(self.web_view, 1 )

        #==========================================
        #rIGHT SIDE: AI SECURITY PANEL
        #==========================================
        self.ai_panel =QFrame()
        self.ai_panel.setObjectName("aiSecurityPanel")
        self.ai_panel.setStyleSheet(f"""
            QFrame#aiSecurityPanel {{
                background-color: {config.COLOR_SURFACE};
                border-left: 1px solid {config.COLOR_BORDER};
            }}
        """)
        ai_layout =QVBoxLayout(self.ai_panel )
        ai_layout.setContentsMargins(20, 20, 20, 20 )
        ai_layout.setSpacing(15 )

        #header
        header_layout =QHBoxLayout()
        icon_label =QLabel("🛡️")
        icon_label.setFont(QFont("Segoe UI Emoji",20 ))

        title_label =QLabel("Security AI")
        title_label.setFont(QFont(config.FONT_FAMILY, 16, QFont.Weight.Bold ))
        title_label.setStyleSheet(f"color: {config.COLOR_PRIMARY};")

        header_layout.addWidget(icon_label )
        header_layout.addWidget(title_label )
        header_layout.addStretch()

        self.buttons_grid =QGridLayout()
        self.buttons_grid.setSpacing(5 )

        self.btn_analyze_page =QPushButton("Analyse Page")
        self.btn_analyze_page.setCursor(Qt.CursorShape.PointingHandCursor )
        self.btn_analyze_page.setStyleSheet(f"""
            QPushButton {{
                background-color: {config.COLOR_WARNING};
                color: #2c3e50;
                border: none;
                border-radius: 15px;
                padding: 6px 15px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #f39c12;
            }}
        """)
        self.btn_analyze_page.clicked.connect(self._trigger_page_analysis )
        self.btn_analyze_page.setVisible(False )#only show after page load
        self.buttons_grid.addWidget(self.btn_analyze_page, 0 ,0 )

        #additional Header Buttons(Hidden on homepage)
        self.dynamic_action_btns =[]

        self.btn_export =QPushButton("Export Report")
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor )
        self.btn_export.setStyleSheet(f"""
            QPushButton {{
                background-color: {config.COLOR_PRIMARY};
                color: white; border: none; border-radius: 12px; padding: 5px 12px;
            }}
        """)
        self.btn_export.clicked.connect(self._export_report )
        self.btn_export.setVisible(False )
        self.buttons_grid.addWidget(self.btn_export, 0 ,1 )
        self.dynamic_action_btns.append(self.btn_export )

        btn_data =[
        ("View SSL",lambda :self._dispatch_tool_worker("ssl",self.url_bar.text())),
        ("IP Info",lambda :self._dispatch_tool_worker("ip",self.url_bar.text())),
        ("Cookies",self._trigger_cookies_tool ),
        ("Scan Links",self._trigger_deep_links_scan )
        ]

        row, col =0, 2 
        for name, callback in btn_data :
            btn =QPushButton(name )
            btn.setCursor(Qt.CursorShape.PointingHandCursor )
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {config.COLOR_LIGHT};
                    color: {config.COLOR_TEXT};
                    border: 1px solid {config.COLOR_BORDER};
                    border-radius: 10px;
                    padding: 4px 10px;
                    font-size: 11px;
                }}
                QPushButton:hover {{
                    background-color: {config.COLOR_BORDER};
                }}
            """)
            btn.clicked.connect(callback )
            btn.setVisible(False )
            self.dynamic_action_btns.append(btn )
            self.buttons_grid.addWidget(btn, row, col )
            col +=1 
            if col >2 :
                col =0 
                row +=1 

                #dashboard / Score Box
        self.score_box =QFrame()
        self.score_box.setObjectName("urlContextBox")
        self.score_box.setStyleSheet(f"""
            QFrame#urlContextBox {{
                background-color: {config.COLOR_BACKGROUND};
                border: 1px solid {config.COLOR_BORDER};
                border-radius: 8px;
            }}
        """)
        self.score_box.hide()#hidden initially until URL loads
        sb_layout =QVBoxLayout(self.score_box )
        self.score_lbl =QLabel("URL Trust Indicator: Pending")
        self.score_lbl.setWordWrap(True )
        self.score_lbl.setFont(QFont(config.FONT_FAMILY, 10, QFont.Weight.Bold ))
        sb_layout.addWidget(self.score_lbl )

        #chat History
        self.chat_display =QTextBrowser()
        self.chat_display.setOpenExternalLinks(True )
        self.chat_display.setStyleSheet(f"""
            QTextBrowser {{
                background-color: transparent;
                border: none;
                font-family: {config.FONT_FAMILY};
                font-size: 14px;
                color: {config.COLOR_TEXT};
            }}
        """)

        #chat input and Send button have been decommissioned to prevent memory/thread crashes
        #the AI Response Display now occupies the full available space

        ai_layout.addLayout(header_layout )
        ai_layout.addLayout(self.buttons_grid )
        ai_layout.addWidget(self.score_box )
        ai_layout.addWidget(self.chat_display, 1 )

        #assemble Splitter
        self.splitter.addWidget(self.browser_container )
        self.splitter.addWidget(self.ai_panel )
        #ratio: 70% browser, 30% panel
        self.splitter.setStretchFactor(0, 7 )
        self.splitter.setStretchFactor(1, 3 )

        main_layout.addWidget(self.splitter )

        #welcome message
        self._append_message("🤖 AI Security Panel",
        "Welcome! Navigate to any website.\n\n"
        "I'll automatically scan it for **phishing threats**, and you can use the **Analyse Page** "
        "button for a deep HTML scam analysis.",
        is_user =False 
        )

        #--- Browser Nav Handlers ---
    def _load_homepage(self ):
        self.url_bar.setText("")
        self.web_view.setUrl(self.homepage_url )
        self.btn_analyze_page.setVisible(False )
        for btn in self.dynamic_action_btns :
            btn.setVisible(False )
        self.score_box.hide()

    def _navigate_entered_url(self ):
        url_text =self.url_bar.text().strip()
        if not url_text :
            return 

        if not url_text.startswith(('http://','https://','file://')):
        #assume search if it contains spaces or no dots
            if ' 'in url_text or '.'not in url_text :
                url_text =f"https://duckduckgo.com/?q={url_text.replace(' ', '+')}"
            else :
                url_text ="https://"+url_text 

                #uI updates
        self.web_view.setUrl(QUrl(url_text ))

        #trigger URL Static Analysis synchronously/rapidly
        self._append_message("🔍 URL Evaluator",f"Running static analysis on `{url_text}`...",False )
        result =SecurityAnalyzer.analyze_url(url_text )
        self._render_url_analysis(result )

    def _nav_back(self ):
        if self.web_view.history().canGoBack():
            self.web_view.back()

    def _nav_forward(self ):
        if self.web_view.history().canGoForward():
            self.web_view.forward()

    def _nav_reload(self ):
        self.web_view.reload()

    def _update_urlbar_on_change(self, qurl ):
    #don't show local asset path for homepage to keep look clean
        url_text =qurl.toString()
        if url_text.endswith("browser_home.html"):
            self.url_bar.setText("")
        else :
            self.url_bar.setText(url_text )

    def _update_loading_progress(self, progress ):
        self.loading_bar.setValue(progress )
        self.loading_bar.setVisible(progress <100 )

    def _on_load_finished(self, ok ):
        self.loading_bar.setValue(0 )
        url_text =self.web_view.url().toString()

        if ok and not url_text.endswith("browser_home.html"):
            self.btn_analyze_page.setVisible(True )
            for btn in self.dynamic_action_btns :
                btn.setVisible(True )
        else :
            self.btn_analyze_page.setVisible(False )
            for btn in self.dynamic_action_btns :
                btn.setVisible(False )


                #--- Custom Security Bridges ---
    def _handle_download(self, downloadItem ):
        url_str =downloadItem.url().toString()
        is_secure_export =getattr(downloadItem ,"_crypto_token","")==self._export_token 
        if url_str.startswith("data:application/pdf")or is_secure_export :
            downloadItem.accept()
            return 

            #state 2: Intercept
        self.btn_download.setText("Permission")
        self.btn_download.setStyleSheet(f"""
            QToolButton {{
                background-color: {config.COLOR_WARNING}; color: #2c3e50; font-weight: bold; border-radius: 0px; padding: 0 10px; border: none;
            }}
        """)

        #add to drawer
        item_widget =QWidget()
        il =QHBoxLayout(item_widget )
        il.setContentsMargins(5, 5 ,5, 5 )

        name_lbl =QLabel(downloadItem.downloadFileName()if downloadItem.downloadFileName()else "Unknown File")
        name_lbl.setStyleSheet("color: #333; font-size: 11px;")

        btn_tick =QPushButton("✔")
        btn_tick.setCursor(Qt.CursorShape.PointingHandCursor )
        btn_tick.setStyleSheet("color: green; border: none; font-weight: bold;")
        btn_cross =QPushButton("✖")
        btn_cross.setCursor(Qt.CursorShape.PointingHandCursor )
        btn_cross.setStyleSheet("color: red; border: none; font-weight: bold;")

        il.addWidget(name_lbl, 1 )
        il.addWidget(btn_tick )
        il.addWidget(btn_cross )

        self.drawer_layout.addWidget(item_widget )
        self.download_drawer.show()

        def on_accept():
        #redirect to user Downloads folder before accepting
            import pathlib 
            dl_dir =str(pathlib.Path.home()/"Downloads")
            try :
                downloadItem.setDownloadDirectory(dl_dir )
            except Exception :
                pass 
            downloadItem.accept()
            item_widget.hide()
            self._check_downloads_complete()

        def on_cancel():
            downloadItem.cancel()
            name_lbl.setStyleSheet("color: red; text-decoration: line-through; opacity: 0.5;")
            name_lbl.setText(name_lbl.text()+" (Denied)")
            btn_tick.hide()
            btn_cross.hide()
            self._check_downloads_complete()

        btn_tick.clicked.connect(on_accept )
        btn_cross.clicked.connect(on_cancel )

    def _check_downloads_complete(self ):
    #update UI to Success State
        self.btn_download.setText("Downloads")
        self.btn_download.setStyleSheet(f"""
            QToolButton {{
                background-color: #2ECC71; color: white; font-weight: bold; border-radius: 0px; padding: 0 10px; border: none;
            }}
        """)

    def _toggle_download_drawer(self ):
        self.download_drawer.setVisible(not self.download_drawer.isVisible())

    def _update_shield_btnUI(self ):
        lvl =getattr(self ,"sm",None )
        if not lvl :return 
        level =self.sm.determine_shield_level()
        if level =="Paranoid":
            bg =config.COLOR_DANGER 
            txt ="Paranoid"
        elif level =="Hardened":
            bg =config.COLOR_WARNING 
            txt ="Hardened"
        else :
            bg =config.COLOR_SAFE 
            txt ="Standard"

        self.btn_security_shield.setText(f"🛡️ {txt}")
        self.btn_security_shield.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent; font-weight: bold; border: 1px solid {bg};
                border-radius: 15px; color: {bg}; padding: 0 10px;
            }}
            QPushButton:hover {{ background-color: {config.COLOR_SURFACE}; border: 2px solid {bg}; }}
        """)

        #make detailed tooltip context mapping visual state
        tip =f"<b>Risk Posture: {txt}</b><br><hr>"
        tip +=f"• JavaScript: {'Off' if self.sm.get('block_js') else 'On'}<br>"
        tip +=f"• Network Trackers: {'Blocked' if self.sm.get('block_trackers') else 'Allowed'}<br>"
        tip +=f"• HTTPS Upgrade: {'Strict' if self.sm.get('strict_https') else 'Off'}<br>"
        tip +=f"• Local Storage: {'Disabled' if self.sm.get('disable_local_storage') else 'Enabled'}<br>"
        tip +=f"• Plugins(PDF/Flash): {'Disabled' if self.sm.get('disable_plugins') else 'Enabled'}<br>"
        tip +=f"• Popups: {'Blocked' if self.sm.get('block_popups') else 'Allowed'}<br>"
        tip +=f"• Screen Capture: {'Disabled' if self.sm.get('disable_screen_capture') else 'Enabled'}<br>"
        tip +=f"• 3rd Party Cookies: {'Blocked' if self.sm.get('block_third_party_cookies') else 'Allowed'}<br>"
        tip +=f"• Auto-Downloads: {'Blocked' if self.sm.get('block_auto_downloads') else 'Allowed'}"

        self.btn_security_shield.setToolTip(tip )

    def _open_advanced_security_panel(self ):
        self.sec_panel =AdvancedSecurityPanel(self.sm, self )
        #ensure that if switches change inside modal, the main tab updates
        self.sec_panel.finished.connect(self._update_shield_btnUI )
        self.sec_panel.exec()

        #--- AI Analysis Panel Handlers ---

    def _render_url_analysis(self, result :dict ):
        self.score_box.show()
        score =result["score"]
        status =result["status"]

        col =config.COLOR_SAFE 
        if status =="SUSPICIOUS":col =config.COLOR_WARNING 
        elif status =="DANGEROUS":col =config.COLOR_DANGER 

        self.score_box.setStyleSheet(f"""
            QFrame#urlContextBox {{
                background-color: {config.COLOR_BACKGROUND};
                border: 2px solid {col};
                border-radius: 8px;
            }}
        """)

        #make summary
        self.score_lbl.setText(f"Link Status: {status}\nFlag Score: {score}\n\nReasons:\n- "+"\n- ".join(result["flags"]))
        fade_in(self.score_box )

    def _trigger_page_analysis(self, _arg =None ):
        if self._is_analyzing :
            return 

        self._is_analyzing =True 
        self.btn_analyze_page.setEnabled(False )

        #simulated chunk progress via QTimer matching recursive DOM extraction
        self.btn_analyze_page.setText("Scanning... 0%")
        self._scan_progress =0 
        if not hasattr(self ,'_scan_timer'):
            self._scan_timer =QTimer(self )
            self._scan_timer.timeout.connect(self._update_scan_progress )
        self._scan_timer.start(100 )

        self._append_message("🔍 Scanner","Extracting full page DOM in chunks to prevent UI locking...",False )

        #async Extraction via Non-Blocking_Chunked_Extraction Web Worker logic
        url_context =self.web_view.url().toString()
        worker_path =os.path.join(self.base_dir ,"assets","Background_Worker.js")
        if os.path.exists(worker_path ):
            with open(worker_path ,"r",encoding ="utf-8")as f :
                js_code =f.read()
        else :
            js_code ="return document.documentElement.outerHTML;"

        self.web_view.page().runJavaScript(js_code, lambda html :self._run_html_worker(html, url_context ))

    def _run_html_worker(self, html :str, url :str ):
    #guard: JS walker may return None/empty on pages that block scripts
        if not html or not html.strip():
            self._append_message("⚠️ Scanner","Page DOM could not be extracted(page may block scripts). Try a different page.",False )
            self._reset_scan_guard()
            return 

        self._active_worker_count +=1 
        worker =Worker(self._thread_analyze_html_payload, html, url )
        worker.signals.result.connect(self._display_page_analysis )
        worker.signals.error.connect(self._on_scan_error )
        worker.signals.finished.connect(self._reset_scan_guard )
        worker.signals.finished.connect(lambda :self._dec_worker_count())
        QThreadPool.globalInstance().start(worker )

    def _on_scan_error(self, err :tuple ):
        self._append_message("❌ Scanner Error",f"Scan failed: {err[1]}",False )

    def _dec_worker_count(self ):
        self._active_worker_count =max(0, self._active_worker_count -1 )

    def _thread_analyze_html_payload(self, html :str, url :str ):
        return SecurityAnalyzer.analyze_page(html, url )

    def _display_page_analysis(self, res :dict ):
        if not res or not isinstance(res, dict ):
            self._append_message("❌ Scanner","Analysis returned no data.",False )
            return 
        self.latest_scan_data =res 

        #save to Tracker db — wrapped so a DB error can't freeze the UI
        try :
            self.parent.db_manager.add_browser_history(
            url =res.get('url',''),
            domain =res.get('domain',''),
            risk_score =res.get('score',0 ),
            risk_level =res.get('status','UNKNOWN'),
            threat_type =' | '.join(res.get('flags',[]))[:255 ]or "None"
            )
            self.parent.db_manager.add_scan("Browser AI Analysis",res.get('url',''),res.get('status',''),res.get('score',0 ))
        except Exception as db_err :
            import logging 
            logging.getLogger(__name__ ).warning("DB write failed during scan: %s",db_err )

            #detailed Markdown Construction
        msg =f"**Deep Page Scan Verdict: {res['status']}** (Threat Score: {res['score']}/100)\n\n"

        #build Detailed Table
        msg +="| Metric | Status |\n|---|---|\n"
        msg +=f"| **HTTPS Secured** | {'✅ Yes' if res['https_status'] else '❌ No'} |\n"
        msg +=f"| **Ext. Scripts** | {res['total_scripts']} |\n"
        msg +=f"| **Hidden Iframes** | {res['hidden_iframes']} |\n"
        msg +=f"| **Password Forms** | {res['password_forms']} |\n"
        msg +=f"| **Executables Linked** | {res['executables_linked']} |\n"
        msg +=f"| **Privacy Risk** | {res['privacy_level']} |\n"

        if res['trackers']:
            msg +="\n**Trackers Blocked:** "+", ".join(res['trackers'])+"\n"

        if res["flags"]:
            msg +="\n**Identified Anomalies & Threats:**\n- "+"\n- ".join(res["flags"])
        else :
            msg +="\nThis page structurally looks consistent."

        if res.get('fake_login_suspect',False )or res['status']=='DANGEROUS':
            msg +="\n\n⚠️ **CRITICAL AI SECURITY WARNING:**\nDo NOT enter your password or personal information here. High risk of credential harvesting or malware deployment detected."
        elif res['status']=='HIGH'or res['status']=='SUSPICIOUS':
            msg +="\n\n⚠️ **AI SECURITY TIP:**\nProceed with absolute caution. Verify the domain carefully before trusting this site with sensitive data."

        self._append_message("🛡️ Advanced AI Scanner",msg, False )

    def _update_scan_progress(self ):
        if self._scan_progress <95 :
            self._scan_progress +=5 
            self.btn_analyze_page.setText(f"Scanning... {self._scan_progress}%")

    def _reset_scan_guard(self ):
        self._is_analyzing =False 
        if hasattr(self ,'_scan_timer')and self._scan_timer.isActive():
            self._scan_timer.stop()
        self.btn_analyze_page.setEnabled(True )
        self.btn_analyze_page.setText("Analyse Page")

        #--- Chat Handlers(Decommissioned) ---
        #_send_chat, _process_chat, _on_chat_error, _on_chat_finished have been removed
        #the interactive chat input interface was decommissioned to eliminate memory/thread
        #crashes. AI interactions now flow exclusively through the toolbar buttons
        #(Analyse Page, View SSL, IP Info, Cookies, Scan Links)

    def _dispatch_tool_worker(self, cmd :str, arg :str ):
        """Run a security tool in a background thread."""
        func =self.tool_map[cmd ]

        def executor():
            return func(arg )

        self._active_worker_count +=1 
        worker =Worker(executor )
        worker.signals.result.connect(lambda r :self._append_message("🛠️ Tool Output",str(r ),False )if r else None )
        worker.signals.error.connect(lambda e :self._append_message("❌ Tool Error",f"Command failed: {e[1]}",False ))
        worker.signals.finished.connect(self._dec_worker_count )
        QThreadPool.globalInstance().start(worker )

    def _run_ssl_tool(self, arg ):
        res =SecurityTools.get_ssl_info(arg )
        if res.get('status')=='success':
            return f"**SSL Details for {arg}:**\n```text\nIssuer: {res['issuer']}\nSubject: {res['subject']}\nExpires: {res['expires']}\n```"
        return f"Error: {res.get('message')}"

    def _run_ip_tool(self, arg ):
        res =SecurityTools.get_ip_info(arg )
        if res.get('status')=='success':
            return f"**IP Lookup**: {res['domain']} resolves to:\n```text\n{res['ip']}\n```"
        return f"Error: {res.get('message')}"

    def _run_headers_tool(self, arg ):
        res =SecurityTools.get_headers(arg )
        if res.get('status')=='success':
            out ="**Security Headers:**\n```text\n"
            for k, v in res['headers'].items():
                out +=f"{k}: {v}\n"
            out +="```"
            return out 
        return f"Error: {res.get('message')}"

    def _run_hash_tool(self, arg ):
        if not arg :return "Error: Please provide text to hash."
        return f"**SHA-256 Hash:**\n`{SecurityTools.generate_hash(arg)}`"

    def _run_whois_tool(self, arg ):
        if not arg :return "Error: URL missing."
        res =SecurityTools.get_whois_info(arg )
        if res.get('status')=='success':
            return f"**WHOIS Record for {res['domain']}:**\n```text\n{res['info']}\n```"
        return f"Error: {res.get('message')}"

    def _run_dns_tool(self, arg ):
        if not arg :return "Error: URL missing."
        res =SecurityTools.get_dns_records(arg )
        if res.get('status')=='success':
            out =f"**DNS Records for {res['domain']}:**\n```text\n"
            for k, v in res['records'].items():
                out +=f"{k}: {', '.join(v) if v else 'None'}\n"
            out +="```"
            return out 
        return f"Error: {res.get('message')}"

    def _run_password_tool(self, arg ):
        pwd =SecurityTools.generate_password(arg if arg else 16 )
        return f"**Generated Password:**\n`{pwd}`\n\n⚠️ *Security Note: Save this password securely. I do NOT store generated passwords!*"

    def _trigger_links_tool(self, _arg =None ):
        self.web_view.page().runJavaScript(
        "Array.from(document.querySelectorAll('a[href]')).map(a => a.href).join('\\n');",
        lambda links :self._append_message("🔗 Links Extracted",f"Found the following links on page:\n```text\n{links[:1500]}{'...' if len(links)>1500 else ''}\n```",False )
        )
        return None 

    def _trigger_deep_links_scan(self ):
        self._append_message("🔗 Link Scanner","Extracting and analyzing all outbound links...",False )
        self.web_view.page().runJavaScript(
        "Array.from(document.querySelectorAll('a[href]')).map(a => a.href).join('\\n');",
        self._execute_deep_links_worker 
        )

    def _execute_deep_links_worker(self, links_blob ):
        if not links_blob :
            self._append_message("🔗 Link Scanner","No links found on this page.",False )
            return 

        def scan_runner():
            urls =[]
            for line in links_blob.split('\n'):
                u =line.strip()
                if u and u.startswith('http')and u not in urls :
                    urls.append(u )

            if not urls :return "No valid HTTP links found."

            out ="**Safe Browsing Link Scan Results:**\n\n| URL | Risk Level | Score |\n|---|---|---|\n"
            #cap at 15 to avoid API/Thread exhaustion
            for u in urls[:15 ]:
                res =SecurityAnalyzer.analyze_url(u )
                safe_u =u[:40 ]+"..."if len(u )>40 else u 
                out +=f"| `{safe_u}` | {res['status']} | {res['score']} |\n"

            if len(urls )>15 :
                out +=f"\n*(+ {len(urls)-15} more links skipped for performance)*"
            return out 

        self._active_worker_count +=1 
        worker =Worker(scan_runner )
        worker.signals.result.connect(lambda r :self._append_message("🔗 Deep Links Scan",str(r ),False )if r else None )
        worker.signals.error.connect(lambda e :self._append_message("❌ Link Scan Error",f"Scan failed: {e[1]}",False ))
        worker.signals.finished.connect(self._dec_worker_count )
        QThreadPool.globalInstance().start(worker )

    def _trigger_cookies_tool(self, _arg =None ):
        self.web_view.page().runJavaScript(
        "document.cookie;",
        lambda c :self._append_message("🍪 Page Cookies",f"**Client-side Cookies:**\n```text\n{c if c else 'No client-side cookies found via Javascript(HttpOnly cookies are protected).'}\n```",False )
        )
        return None 

    def _get_downloads_dir(self )->str :
        """Returns the user's Downloads folder(works in both dev and frozen.exe)."""
        import pathlib 
        downloads =pathlib.Path.home()/"Downloads"
        downloads.mkdir(exist_ok =True )
        return str(downloads )

    def _export_report(self ):
        if not self.latest_scan_data :
            self._append_message("⚙️ System","No security report available to export. Please run 'Analyse Page' first.",False )
            return 

        try :
            timestamp =datetime.now().strftime("%Y%m%d_%H%M%S")
            domain =self.latest_scan_data.get('domain','unknown')
            reports_dir =self._get_downloads_dir()

            #export JSON
            json_payload =ReportGenerator.generate_json_report(self.latest_scan_data )
            json_path =os.path.join(reports_dir, f"{domain}_{timestamp}.json")
            with open(json_path ,"w",encoding ="utf-8")as f :
                f.write(json_payload )

                #export HTML
            html_payload =ReportGenerator.generate_html_report(self.latest_scan_data )
            html_path =os.path.join(reports_dir, f"{domain}_{timestamp}.html")
            with open(html_path ,"w",encoding ="utf-8")as f :
                f.write(html_payload )

                #export PDF
            pdf_path =os.path.join(reports_dir, f"{domain}_{timestamp}.pdf")
            doc =QTextDocument()
            doc.setHtml(html_payload )
            pdf_writer =QPdfWriter(pdf_path )
            pdf_writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4 ))
            pdf_writer.setPageMargins(QMarginsF(15, 15, 15, 15 ))
            doc.print(pdf_writer )

            self._append_message("💾 Export Success",
            f"Report saved to your **Downloads** folder:\n- `{os.path.basename(html_path)}`\n- `{os.path.basename(json_path)}`\n- `{os.path.basename(pdf_path)}`",
            False )
        except Exception as e :
            self._append_message("❌ Export Error",f"Failed to save reports: {e}",False )

            #_display_chat_response removed — chat thread decommissioned

    def _append_message(self, sender :str, text :str, is_user :bool ):
    #uI_SANITIZER: Strip literal newline artifacts mapped by AI
        text =str(text ).replace('\\n','\n')

        #convert markdown to basic HTML for QTextBrowser
        try :
            html_content =markdown.markdown(text, extensions =['fenced_code','tables'])
        except Exception as e :
        #fallback if markdown library fails in PyInstaller bundle
            import html 
            import re 
            safe_text =html.escape(str(text ))
            safe_text =re.sub(r'\*\*(.*?)\*\*',r'<b>\1</b>',safe_text )
            safe_text =re.sub(r'\*(.*?)\*',r'<b>\1</b>',safe_text )
            html_content =safe_text.replace('\n','<br>')

            #apply style classes based on sender
        align ="right"if is_user else "left"
        bg_col ="#e8f4fd"if is_user else "#f5f6fa"
        text_col ="#2c3e50"

        #cOMMAND_VIEW override for pre blocks
        pre_css ="background-color: #1e1e1e !important; color: #d4d4d4 !important; padding: 10px; border-radius: 5px; box-shadow: none !important; backdrop-filter: none !important;"

        msg_html =f"""
        <style>pre {{ {pre_css} }}</style>
        <div style="margin-bottom: 12px; text-align: {align};">
            <span style="font-size: 11px; color: {config.COLOR_SECONDARY}; margin-bottom: 2px; display: inline-block;">
                <b>{sender}</b>
            </span><br>
            <div style="display: inline-block; text-align: left; background-color: {bg_col}; 
                        color: {text_col}; padding: 10px 14px; border-radius: 12px; 
                        max-width: 85%; font-family: '{config.FONT_FAMILY}'; border: 1px solid {config.COLOR_BORDER};">
                {html_content}
            </div>
        </div>
        """
        self.chat_display.append(msg_html )

        #scroll to bottom smoothly
        scrollbar =self.chat_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
