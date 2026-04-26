"""

Phishing Threat Detection Interface.



Provides real-time URL analysis capabilities, leveraging the ML classification

engine to assess risk levels. Features interactive testing tools and detailed

forensic breakdowns of analyzed URLs.

"""

from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QLabel, 

QLineEdit, QPushButton, QTextEdit, QGroupBox, QFrame, 

QScrollArea )

from PyQt6.QtCore import Qt, QThreadPool 

from PyQt6.QtGui import QFont 

from utils.workers import Worker 

import config 





class PhishingTab(QWidget ):

    """

    User interface for the Phishing Detection module.

    

    Attributes:

        url_input(QLineEdit): Input field for target URLs.

        results_layout(QVBoxLayout): Dynamic container for analysis reports.

    """



    def __init__(self, parent ):

        """setup the tab layout and event handlers."""

        super().__init__()

        self.parent =parent 

        #guard: prevents concurrent workers from rapid button clicks

        self._is_analyzing =False 

        self.init_ui()



    def init_ui(self ):

        """setup UI"""

        layout =QVBoxLayout()

        layout.setSpacing(20 )



        #title

        title =QLabel("\U0001f517 Phishing URL Detector")

        title.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        layout.addWidget(title )



        #description

        desc =QLabel("Enter a URL to check if it's a phishing attempt. "

        "The AI will analyze the URL and provide a risk assessment.")

        desc.setWordWrap(True )

        desc.setStyleSheet("color: gray;")

        layout.addWidget(desc )



        #input section

        input_group =QGroupBox("URL Input")

        input_layout =QVBoxLayout()



        url_layout =QHBoxLayout()

        self.url_input =QLineEdit()

        self.url_input.setPlaceholderText("Enter URL(e.g., https://example.com)")

        self.url_input.returnPressed.connect(self.analyze_url )



        self._analyze_btn =QPushButton("🔍 Analyze URL")

        self._analyze_btn.clicked.connect(self.analyze_url )



        url_layout.addWidget(self.url_input, 3 )

        url_layout.addWidget(self._analyze_btn, 1 )



        input_layout.addLayout(url_layout )



        #quick test buttons

        quick_test_layout =QHBoxLayout()

        quick_test_label =QLabel("Quick Tests:")

        quick_test_label.setStyleSheet("font-weight: bold;")



        self._safe_btn =QPushButton("Test Safe URL")

        self._safe_btn.clicked.connect(self._test_safe_url )



        self._suspicious_btn =QPushButton("Test Suspicious URL")

        self._suspicious_btn.clicked.connect(self._test_suspicious_url )



        self._malicious_btn =QPushButton("Test Malicious URL")

        self._malicious_btn.clicked.connect(self._test_malicious_url )



        quick_test_layout.addWidget(quick_test_label )

        quick_test_layout.addWidget(self._safe_btn )

        quick_test_layout.addWidget(self._suspicious_btn )

        quick_test_layout.addWidget(self._malicious_btn )

        quick_test_layout.addStretch()



        input_layout.addLayout(quick_test_layout )

        input_group.setLayout(input_layout )

        layout.addWidget(input_group )



        #results section — wrapped in QScrollArea so 3-card result set doesn't overflow

        self.results_group =QGroupBox("Analysis Results")

        results_outer_layout =QVBoxLayout()



        scroll =QScrollArea()

        scroll.setWidgetResizable(True )

        scroll.setFrameShape(QFrame.Shape.NoFrame )



        results_container =QWidget()

        self.results_layout =QVBoxLayout(results_container )

        self.results_layout.setContentsMargins(0, 5 ,0, 5 )

        self.results_layout.setAlignment(Qt.AlignmentFlag.AlignTop )



        self.results_placeholder =QLabel("Enter a URL and click 'Analyze' to see results")

        self.results_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.results_placeholder.setStyleSheet("color: gray; padding: 40px;")

        self.results_layout.addWidget(self.results_placeholder )



        scroll.setWidget(results_container )

        results_outer_layout.addWidget(scroll )

        self.results_group.setLayout(results_outer_layout )

        self.results_group.setMinimumHeight(250 )

        layout.addWidget(self.results_group )



        layout.addStretch()

        self.setLayout(layout )



    def test_url(self, url :str ):

        """Test a predefined URL"""

        self.url_input.setText(url )

        self.analyze_url()



    def _test_safe_url(self ):

        """Test with a known-safe URL — bypasses ML to use deterministic rule engine."""

        self._analyze_with_rules("https://www.google.com")



    def _test_suspicious_url(self ):

        """Test with a suspicious URL — bypasses ML to use deterministic rule engine."""

        self._analyze_with_rules("http://paypa1-verify-account-login.suspiciousdomain.xyz/secure/update")



    def _test_malicious_url(self ):

        """Test with a malicious URL — bypasses ML to use deterministic rule engine."""

        self._analyze_with_rules("http://192.168.1.1/free-prize-winner-claim-your-lottery-reward-verify-bank-account-update-credentials-now.php?token = abc&ref = phish&id = steal&session = harvest")



    def _set_buttons_enabled(self, enabled :bool ):

        """Enable or disable all URL action buttons atomically."""

        for btn in(self._analyze_btn, self._safe_btn, 

        self._suspicious_btn, self._malicious_btn ):

            btn.setEnabled(enabled )



    def _analyze_with_rules(self, url :str ):

        """Analyze a URL using the deterministic rule-based engine(for test buttons)."""

        if self._is_analyzing :

            return 

        self._is_analyzing =True 

        self._set_buttons_enabled(False )

        self.url_input.setText(url )



        #clear previous results

        while self.results_layout.count():

            child =self.results_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



        self.loading_label =QLabel("Analyzing URL, please wait...")

        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.loading_label.setStyleSheet("color: #666; padding: 40px; font-style: italic;")

        self.results_layout.addWidget(self.loading_label )



        from browser.security_analyzer import SecurityAnalyzer 

        import config as _cfg 



        def _rule_analyze():

            res =SecurityAnalyzer.analyze_url(url )

            #map SecurityAnalyzer output to PhishingDetector format

            score_val =res.get('score',0 )/100.0 

            #classify strictly by score thresholds(aligned with phishing detector)

            if score_val <=0.40 :

                classification ='safe'

                color =_cfg.COLOR_SAFE 

            elif score_val <=0.85 :

                classification ='suspicious'

                color =_cfg.COLOR_WARNING 

            else :

                classification ='malicious'

                color =_cfg.COLOR_DANGER 

            return {

            'url':url ,

            'risk_score':score_val ,

            'classification':classification ,

            'color':color ,

            'explanation':'\n'.join(res.get('flags',['No flags.'])),

            'features':{

            'url_length':len(url ),

            'has_https':url.startswith('https'),

            'suspicious_keywords':sum(1 for kw in[

            'login','verify','reset','secure','account','bank','billing','confirm','free','prize'

            ]if kw in url.lower())

            }

            }



        self._current_eval_url =url 

        worker =Worker(_rule_analyze )

        worker.signals.result.connect(self._on_worker_result )

        worker.signals.error.connect(self._on_worker_error )

        QThreadPool.globalInstance().start(worker )



    def analyze_url(self ):

        """Analyze the entered URL asynchronously.

        

        Guard: if a worker is already in-flight, this call is a no-op.

        All analysis runs in a QRunnable worker; the main thread only

        updates the UI via the connected signal slots.

        """

        #prevent concurrent workers from rapid repeated clicks

        if self._is_analyzing :

            return 



        url =self.url_input.text().strip()

        if not url :

            return 



            #lock UI before starting worker

        self._is_analyzing =True 

        self._set_buttons_enabled(False )



        #clear previous results and show loading state

        while self.results_layout.count():

            child =self.results_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



        self.loading_label =QLabel("Analyzing URL, please wait...")

        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.loading_label.setStyleSheet("color: #666; padding: 40px; font-style: italic;")

        self.results_layout.addWidget(self.loading_label )



        from ui.animations import LoadingAnimation 

        self.loading_anim =LoadingAnimation(self.loading_label.setText ,"Analyzing URL, please wait")

        self.loading_anim.start()



        #start worker — analysis runs entirely off the main thread

        self._current_eval_url =url 

        worker =Worker(self.parent.phishing_detector.analyze_url, url )

        worker.signals.result.connect(self._on_worker_result )

        worker.signals.error.connect(self._on_worker_error )

        QThreadPool.globalInstance().start(worker )



    def _on_worker_result(self, result :dict ):

        """Slot — called on main thread by Qt signal dispatch."""

        if hasattr(self ,'loading_anim'):

            self.loading_anim.stop()

            #always release the lock and restore buttons first

        self._is_analyzing =False 

        self._set_buttons_enabled(True )

        url =result.get('url',getattr(self ,'_current_eval_url',''))

        self._handle_analysis_result(result, url )



    def _on_worker_error(self, err :tuple ):

        """Slot — called on main thread by Qt signal dispatch."""

        if hasattr(self ,'loading_anim'):

            self.loading_anim.stop()

            #always release the lock and restore buttons first

        self._is_analyzing =False 

        self._set_buttons_enabled(True )

        self.display_error(f"Analysis failed: {err[1]}")



    def _handle_analysis_result(self, result :dict, url :str ):

        """Process the background worker result and update the UI"""

        #clear loading placeholder

        while self.results_layout.count():

            child =self.results_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



                #display results

        if 'error'in result :

            self.display_error(result.get('error','Unknown error occurred'))

        else :

            self.display_results(result )



            #log scan

            try :

                self.parent.db.add_scan(

                'phishing_url',

                url, 

                result.get('classification','unknown'),

                result.get('risk_score',0.0 )

                )



                #add alert if malicious

                if result.get('risk_score',0.0 )>0.85 :

                    self.parent.db.add_alert(

                    'phishing',

                    'high',

                    f"Malicious URL detected: {url[:50]}...",

                    result.get('explanation','No explanation available')

                    )

            except Exception as db_error :

                print(f"Database error(non-critical): {db_error}")



                #award XP

            try :

                self.parent.gamification.award_scan_xp()

            except Exception as xp_error :

                print(f"XP award error(non-critical): {xp_error}")



    def display_error(self, error_msg :str ):

        """Display error message"""

        error_label =QLabel(f"❌ Error: {error_msg}")

        error_label.setStyleSheet(f"color: {config.COLOR_DANGER}; font-weight: bold; padding: 20px;")

        error_label.setWordWrap(True )

        self.results_layout.addWidget(error_label )



    def display_results(self, result :dict ):

        """Display analysis results"""

        #risk score card

        score_card =self.create_score_card(result )

        self.results_layout.addWidget(score_card )



        #details

        details_widget =self.create_details_widget(result )

        self.results_layout.addWidget(details_widget )



        #explanation

        explanation_widget =self.create_explanation_widget(result )

        self.results_layout.addWidget(explanation_widget )



    def create_score_card(self, result :dict )->QWidget :

        """Create risk score display card"""

        frame =QFrame()

        frame.setFrameStyle(QFrame.Shape.StyledPanel )

        score =result.get('risk_score',0.0 )

        is_malicious =score >0.85 



        if is_malicious :

            bg_color =config.COLOR_DANGER 

            classification_text ="MALICIOUS"

            icon ="✗"

            text_color ="white"

        elif score >0.40 :

            bg_color =config.COLOR_WARNING 

            classification_text ="SUSPICIOUS"

            icon ="⚠"

            text_color ="#2c3e50"

        else :

            bg_color =config.COLOR_SAFE 

            classification_text ="SAFE"

            icon ="✓"

            text_color ="#2c3e50"



        frame.setStyleSheet(f"""

            QFrame {{

                background-color: {bg_color};

                border-radius: 10px;

                padding: 20px;

            }}

            QLabel {{

                color: {text_color};

            }}

        """)



        layout =QVBoxLayout()



        classification_label =QLabel(f"{icon} {classification_text}")

        classification_label.setFont(QFont("Segoe UI",28, QFont.Weight.Bold ))

        classification_label.setAlignment(Qt.AlignmentFlag.AlignCenter )



        #risk score

        risk_score =QLabel(f"Risk Score: {result['risk_score']:.1%}")

        risk_score.setFont(QFont("Segoe UI",16 ))

        risk_score.setAlignment(Qt.AlignmentFlag.AlignCenter )



        layout.addWidget(classification_label )

        layout.addWidget(risk_score )



        frame.setLayout(layout )

        return frame 



    def create_details_widget(self, result :dict )->QWidget :

        """Create details widget"""

        group =QGroupBox("URL Details")

        layout =QVBoxLayout()



        #uRL

        url_label =QLabel(f"<b>URL:</b> {result['url']}")

        url_label.setWordWrap(True )

        layout.addWidget(url_label )



        #features

        features =result.get('features',{})

        features_text =f"<b>Length:</b> {features.get('url_length', 'N/A')} characters | "

        features_text +=f"<b>HTTPS:</b> {'Yes' if features.get('has_https', False) else 'No'} | "

        features_text +=f"<b>Suspicious Keywords:</b> {features.get('suspicious_keywords', 0)}"



        features_label =QLabel(features_text )

        layout.addWidget(features_label )



        group.setLayout(layout )

        return group 



    def create_explanation_widget(self, result :dict )->QWidget :

        """Create explanation widget"""

        group =QGroupBox("Detailed Analysis")

        layout =QVBoxLayout()



        explanation =QTextEdit()

        explanation.setReadOnly(True )

        explanation.setPlainText(result.get('explanation','No explanation available'))

        explanation.setMaximumHeight(150 )



        layout.addWidget(explanation )



        group.setLayout(layout )

        return group 

