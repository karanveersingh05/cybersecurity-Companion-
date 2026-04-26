"""

Application Root Controller.



setup the main graphical interface, instantiates core business logic subsystems

(Detectors, Assistant, Auditor), and manages the high-level navigation lifecycle.

"""

from PyQt6.QtWidgets import(QMainWindow, QTabWidget, QWidget, QVBoxLayout, 

QStatusBar, QLabel )

from PyQt6.QtCore import Qt, QTimer, QThreadPool 

from PyQt6.QtGui import QFont, QIcon 

import config 

from database import DatabaseManager 

from detection import PhishingDetector, AnomalyDetector 

from assistant import SecurityAssistant 

from auditor import ModelAuditor 

from gamification import GamificationManager 

from utils import get_system_stats 

from utils.workers import Worker 



#lazy imports for tabs to avoid circular dependencies and speed up startup

#from.dashboard_tab import DashboardTab

#... (imported dynamically in init_ui)





class MainWindow(QMainWindow ):

    """

    Primary application container.

    

    Attributes:

        db(DatabaseManager): Persistence layer interface.

        phishing_detector(PhishingDetector): URL analysis engine.

        anomaly_detector(AnomalyDetector): Log analysis engine.

        assistant(SecurityAssistant): RAG-based help system.

        auditor(ModelAuditor): ML governance subsystem.

        gamification(GamificationManager): User engagement tracker.

    """



    def __init__(self ):

        """setup core systems and launch UI construction."""

        super().__init__()



        #instantiate business logic layer

        self.db =DatabaseManager()

        #setup core UI container

        self.db =DatabaseManager()

        self.gamification =GamificationManager(self.db )



        #models are lazy-loaded on access to prevent RAM spiking / swapping on weak machines

        self._phishing_detector =None 

        self._anomaly_detector =None 

        self._assistant =None 

        self._auditor =None 



        self.init_ui()



        #configure periodic system health monitoring

        self.status_timer =QTimer()

        self.status_timer.timeout.connect(self.update_status_bar )

        self.status_timer.start(5000 )#polling interval: 5s



    def init_ui(self ):

        """build the main window layout and navigation tabs."""

        self.setWindowTitle(f"{config.APP_NAME} v{config.APP_VERSION}")

        self.setMinimumSize(1200, 800 )



        #brand Identity

        if config.ICON_PATH.exists():

            self.setWindowIcon(QIcon(str(config.ICON_PATH )))



            #apply Global Design System

        self.setStyleSheet(self.get_stylesheet())



        #navigation container

        self.tabs =QTabWidget()

        self.tabs.setDocumentMode(True )

        self.setCentralWidget(self.tabs )



        #dynamic Tab Loading to manage dependencies

        from.dashboard_tab import DashboardTab 

        from.phishing_tab import PhishingTab 

        from.anomaly_tab import AnomalyTab 

        from.assistant_tab import AssistantTab 

        from.auditor_tab import AuditorTab 

        from.training_tab import TrainingTab 

        from.browser_tab import BrowserTab 



        #populate Navigation

        self.tabs.addTab(DashboardTab(self ),"🏠 Dashboard")

        self.tabs.addTab(PhishingTab(self ),"🔗 Phishing Detector")

        self.tabs.addTab(AnomalyTab(self ),"📊 Log Analyzer")

        self.tabs.addTab(AssistantTab(self ),"🤖 AI Assistant")

        self.tabs.addTab(AuditorTab(self ),"🔍 Model Auditor")

        self.tabs.addTab(BrowserTab(self ),"🌐 Secure Browser")

        self.tabs.addTab(TrainingTab(self ),"🎓 Security Training")



        #uI Animation Hook

        from.animations import fade_in 

        self.tabs.currentChanged.connect(lambda index :fade_in(self.tabs.widget(index ),duration =300 ))



        #system Status Footer

        self.status_bar =QStatusBar()

        self.setStatusBar(self.status_bar )

        self.update_status_bar()



    @property 

    def phishing_detector(self ):

        if self._phishing_detector is None :

            self.status_bar.showMessage("Lazy-loading Phishing Detector model...")

            from detection import PhishingDetector 

            self._phishing_detector =PhishingDetector()

            self.status_bar.clearMessage()

        return self._phishing_detector 



    @property 

    def anomaly_detector(self ):

        if self._anomaly_detector is None :

            self.status_bar.showMessage("Lazy-loading Log Anomaly model...")

            from detection import AnomalyDetector 

            self._anomaly_detector =AnomalyDetector()

            self.status_bar.clearMessage()

        return self._anomaly_detector 



    @property 

    def assistant(self ):

        if self._assistant is None :

            self.status_bar.showMessage("Lazy-loading RAG Assistant and FAISS index...")

            from assistant import SecurityAssistant 

            self._assistant =SecurityAssistant()

            self.status_bar.clearMessage()

        return self._assistant 



    @property 

    def auditor(self ):

        if self._auditor is None :

            from auditor import ModelAuditor 

            self._auditor =ModelAuditor()

        return self._auditor 



    def update_status_bar(self ):

        """Refresh system health metrics in the footer via a background worker.

        

        psutil.cpu_percent() can block briefly; running it on the UI thread

        causes periodic jank. This offloads collection and only updates the

        QStatusBar label from the main thread via Qt signal dispatch.

        """

        worker =Worker(self._collect_status_data )

        worker.signals.result.connect(self._apply_status_bar )

        QThreadPool.globalInstance().start(worker )



    def _collect_status_data(self )->dict :

        """Collect stats in a background thread."""

        return {

        'stats':get_system_stats(),

        'security_score':self.db.get_security_score(),

        }



    def _apply_status_bar(self, data :dict ):

        """Update the status bar label — called on the main thread."""

        stats =data['stats']

        security_score =data['security_score']



        status_text =f"Security Score: {security_score}/100 | "

        status_text +=f"CPU: {stats.get('cpu_usage', 0):.1f}% | "

        status_text +=f"Memory: {stats.get('memory_usage', 0):.1f}% | "

        status_text +=f"{config.APP_NAME} v{config.APP_VERSION}"



        self.status_bar.showMessage(status_text )



    def get_stylesheet(self )->str :

        """

        Define the global CSS styling for the application.

        

        adds a flat, modern design language with consistent branding colors

        defined in the config module.

        """

        return f"""

            QMainWindow {{

                background-color: #f5f6fa;

            }}

            

            QTabWidget::pane {{

                border: 1px solid {config.COLOR_LIGHT};

                background-color: white;

                border-radius: 0px;

                top: -1px; 

            }}

            

            QTabBar::tab {{

                background-color: {config.COLOR_LIGHT};

                color: #555;

                padding: 12px 24px;

                margin-right: 4px;

                border-top-left-radius: 0px;

                border-top-right-radius: 0px;

                font-family: "Segoe UI";

                font-size: 13px;

                font-weight: 600;

            }}

            

            QTabBar::tab:selected {{

                background-color: white;

                color: {config.COLOR_PRIMARY};

                border-bottom: 2px solid {config.COLOR_PRIMARY};

            }}

            

            QTabBar::tab:hover {{

                background-color: #dfe4ea;

                color: {config.COLOR_DARK};

            }}

            

            QPushButton {{

                background-color: {config.COLOR_PRIMARY};

                color: white;

                border: none;

                padding: 10px 20px;

                border-radius: 0px;

                font-family: "Segoe UI";

                font-size: 13px;

                font-weight: 600;

            }}

            

            QPushButton:hover {{

                background-color: #2980b9;

            }}

            

            QPushButton:pressed {{

                background-color: #21618c;

            }}

            

            QLineEdit, QTextEdit, QPlainTextEdit {{

                border: 1px solid #dcdcdc;

                border-radius: 0px;

                padding: 10px;

                font-family: "Segoe UI";

                font-size: 13px;

                background-color: white;

                color: #2c3e50;

                selection-background-color: {config.COLOR_PRIMARY};

                selection-color: white;

            }}

            

            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{

                border: 2px solid {config.COLOR_PRIMARY};

            }}

            

            QLabel {{

                color: {config.COLOR_DARK};

                font-family: "Segoe UI";

                font-size: 13px;

            }}

            

            QGroupBox {{

                border: 1px solid {config.COLOR_LIGHT};

                border-radius: 0px;

                margin-top: 22px;

                font-weight: 600;

                padding-top: 8px;

                padding: 15px;

                background-color: white;

            }}

            

            QGroupBox::title {{

                subcontrol-origin: margin;

                left: 10px;

                padding: 0 5px;

                color: #555;

            }}

            

            QProgressBar {{

                border: none;

                background-color: {config.COLOR_LIGHT};

                border-radius: 0px;

                text-align: center;

                font-weight: bold;

                color: {config.COLOR_DARK};

            }}

            

            QProgressBar::chunk {{

                background-color: {config.COLOR_PRIMARY};

                border-radius: 0px;

            }}

            

            QStatusBar {{

                background-color: {config.COLOR_DARK};

                color: #ecf0f1;

                font-family: "Consolas", monospace;

                font-size: 12px;

            }}

        """

