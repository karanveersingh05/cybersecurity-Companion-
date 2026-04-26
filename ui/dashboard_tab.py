"""

Executive Security Dashboard.



Provides a unified view of the system's security posture, aggregating data 

from various scanning modules and presenting key performance indicators(KPIs) 

such as the composite security score and active alert metrics.

"""

from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QLabel, 

QGroupBox, QGridLayout, QPushButton, QFrame, 

QScrollArea, QProgressBar )

from PyQt6.QtCore import Qt, QTimer, QThreadPool 

from PyQt6.QtGui import QFont, QPixmap 

import config 

from utils import format_timestamp 

from utils.workers import Worker 





class DashboardTab(QWidget ):

    """

    Central visualization component for security telemetry.

    

    Attributes:

        refresh_timer(QTimer): Orchestrates periodic data polling.

        score_label(QLabel): Displays real-time aggregate security score.

        stats_labels(Dict[str, QLabel]): Dynamic references to stat widgets.

    """



    def __init__(self, parent ):

        """setup dashboard layout and polling mechanisms."""

        super().__init__()

        self.parent =parent 

        self._is_refreshing =False #guard: prevents stacked refresh workers

        self.init_ui()



        #configure autonomous data refresh cycle

        self.refresh_timer =QTimer()

        self.refresh_timer.timeout.connect(self.refresh_dashboard )

        self.refresh_timer.start(10000 )#polling interval: 10s



        #connect gamification signal to auto-refresh when XP changes

        self.parent.gamification.xp_updated.connect(self.refresh_dashboard )



    def init_ui(self ):

        """build the visual hierarchy of the dashboard."""

        #inner container for scrollable content

        container =QWidget()

        layout =QVBoxLayout(container )

        layout.setSpacing(20 )

        layout.setContentsMargins(15, 15, 15, 15 )



        #brand Identity / Logo

        if config.LOGO_PATH.exists():

            logo_label =QLabel()

            pixmap =QPixmap(str(config.LOGO_PATH ))

            if not pixmap.isNull():

            #resample for smooth rendering at display size

                logo_label.setPixmap(pixmap.scaledToHeight(80, Qt.TransformationMode.SmoothTransformation ))

                logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

                layout.addWidget(logo_label )



                #header

        title =QLabel("Security Operations Center")

        title.setFont(QFont("Segoe UI",24, QFont.Weight.Bold ))

        title.setAlignment(Qt.AlignmentFlag.AlignCenter )

        layout.addWidget(title )



        #key Performance Indicator(Score)

        score_card =self.create_security_score_card()

        layout.addWidget(score_card )



        #operational Metrics Grid

        stats_grid =self.create_stats_grid()

        layout.addWidget(stats_grid )



        #real-time Alert Feed

        alerts_box =self.create_alerts_box()

        layout.addWidget(alerts_box )



        #manual Override Controls

        refresh_btn =QPushButton("\U0001f504 Force Refresh Telemetry")

        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        refresh_btn.clicked.connect(self.refresh_dashboard )

        layout.addWidget(refresh_btn )



        layout.addStretch()



        #wrap in scroll area so content is accessible at any window height / DPI

        scroll =QScrollArea()

        scroll.setWidget(container )

        scroll.setWidgetResizable(True )

        scroll.setFrameShape(QFrame.Shape.NoFrame )



        outer =QVBoxLayout(self )

        outer.setContentsMargins(0, 0 ,0, 0 )

        outer.addWidget(scroll )



        #hydrate initial state

        self.refresh_dashboard()



    def create_security_score_card(self )->QWidget :

        """

        Render the primary security score visualization.

        

        Uses a stylized QFrame to present the aggregate risk score with 

        color-coded feedback(Safe/Warning/Critical).

        """

        card =QFrame()

        card.setObjectName("securityScoreCard")

        card.setFrameShape(QFrame.Shape.StyledPanel )



        #scoped selector prevents color leaking into sibling/parent QLabels

        card.setStyleSheet(f"""

            QFrame#securityScoreCard {{

                background-color: {config.COLOR_PRIMARY};

                border-radius: 12px;

                padding: 24px;

            }}

            QFrame#securityScoreCard QLabel {{

                color: #fFFFFF;

                font-weight: bold;

            }}

        """)



        layout =QVBoxLayout()



        self.score_label =QLabel("--")

        self.score_label.setFont(QFont("Segoe UI",48, QFont.Weight.Bold ))

        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter )



        subtitle =QLabel("Composite Security Score")

        subtitle.setFont(QFont("Segoe UI",14 ))

        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter )



        layout.addWidget(self.score_label )

        layout.addWidget(subtitle )



        card.setLayout(layout )

        return card 



    def create_stats_grid(self )->QWidget :

        """

        Render the operational statistics matrix.

        

        Displays key metrics like total scans performed, threat levels, and 

        system engagement(XP).

        """

        group =QGroupBox("System Telemetry")

        group.setFont(QFont("Segoe UI",10 ))

        layout =QGridLayout()

        layout.setVerticalSpacing(15 )

        layout.setHorizontalSpacing(20 )

        #balanced stretch: description cols get more space than value cols

        layout.setColumnStretch(0, 3 )

        layout.setColumnStretch(1, 2 )

        layout.setColumnStretch(2, 3 )

        layout.setColumnStretch(3, 2 )



        self.stats_labels ={}

        #config: (Key, Display Label)

        stats_config =[

        ('scans','Total Scans Performed'),

        ('alerts','Active Threat Alerts'),

        ('level','Security Clearance Level'),

        ('xp','System Knowledge(XP)')

        ]



        for i ,(key, label )in enumerate(stats_config ):

            row =i //2 

            col =(i %2 )*2 



            label_widget =QLabel(label )

            label_widget.setFont(QFont("Segoe UI",10, QFont.Weight.DemiBold ))

            label_widget.setStyleSheet("color: #666;")



            value_widget =QLabel("--")

            value_widget.setFont(QFont("Segoe UI",12, QFont.Weight.Bold ))

            value_widget.setStyleSheet(f"color: {config.COLOR_PRIMARY};")



            layout.addWidget(label_widget, row, col )

            layout.addWidget(value_widget, row, col +1 )



            self.stats_labels[key ]=value_widget 



            #add XP Progress Bar

        self.xp_progress_bar =QProgressBar()

        self.xp_progress_bar.setStyleSheet(f"""

            QProgressBar {{

                border: 1px solid #ddd;

                border-radius: 6px;

                text-align: center;

                height: 18px;

            }}

            QProgressBar::chunk {{

                background-color: {config.COLOR_PRIMARY};

                border-radius: 5px;

            }}

        """)



        layout.addWidget(QLabel("Progress to Next Level:"),2, 0 )

        layout.addWidget(self.xp_progress_bar, 2 ,1, 1 ,3 )



        group.setLayout(layout )

        return group 



    def create_alerts_box(self )->QWidget :

        """

        setup the container for the recent alerts feed.

        """

        group =QGroupBox("Recent Intelligence & Alerts")

        group.setFont(QFont("Segoe UI",10 ))

        layout =QVBoxLayout()



        #scroll area for potentially long alert lists — capped so it actually scrolls

        scroll =QScrollArea()

        scroll.setWidgetResizable(True )

        scroll.setFrameShape(QFrame.Shape.NoFrame )

        scroll.setStyleSheet("background: transparent;")

        scroll.setMaximumHeight(220 )



        container_widget =QWidget()

        self.alerts_container =QVBoxLayout(container_widget )

        self.alerts_container.setContentsMargins(0, 0 ,0, 0 )

        self.alerts_container.setSpacing(10 )



        scroll.setWidget(container_widget )

        layout.addWidget(scroll )



        group.setLayout(layout )

        group.setFixedHeight(280 )



        return group 



    def refresh_dashboard(self ):

        """

        Synchronize UI state with the latest backend data.

        

        All DB queries are offloaded to a QThreadPool worker to keep the

        UI thread unblocked during the 10-second polling cycle.

        """

        if self._is_refreshing :

            return 

        self._is_refreshing =True 

        worker =Worker(self._fetch_dashboard_data )

        worker.signals.result.connect(self._apply_dashboard_data )

        worker.signals.finished.connect(lambda :setattr(self ,'_is_refreshing',False ))

        QThreadPool.globalInstance().start(worker )



    def _fetch_dashboard_data(self )->dict :

        """Collect all dashboard metrics in a background thread."""

        return {

        'score':self.parent.db.get_security_score(),

        'progress':self.parent.gamification.get_user_stats(),

        'alerts_count':self.parent.db.get_active_alerts_count(),

        'recent_alerts':self.parent.db.get_recent_alerts(5 ),

        }



    def _apply_dashboard_data(self, data :dict ):

        """

        Update UI widgets from fetched data — runs on the main thread

        via Qt signal dispatch.

        """

        score =data['score']

        self.score_label.setText(f"{score}")



        #dynamic color coding based on risk thresholds

        if score >=80 :

            color =config.COLOR_SAFE 

            text_color ="#FFFFFF"#white on green — sufficient contrast

        elif score >=50 :

            color =config.COLOR_WARNING 

            text_color ="#2c3e50"#dark text on amber — WCAG AA compliant

        else :

            color =config.COLOR_DANGER 

            text_color ="#FFFFFF"#white on red — sufficient contrast



            #apply updated style using scoped selector to prevent color leakage

        self.score_label.parentWidget().setStyleSheet(f"""

            QFrame#securityScoreCard {{

                background-color: {color};

                border-radius: 12px;

                padding: 24px;

            }}

            QFrame#securityScoreCard QLabel {{

                color: {text_color};

                font-weight: bold;

            }}

        """)



        #2. Update Operational Metrics

        progress =data['progress']

        self.stats_labels['scans'].setText(str(progress['scans_performed']))

        self.stats_labels['level'].setText(str(progress['level']))

        self.stats_labels['xp'].setText(f"{progress['total_xp']:,}")



        #update progress bar

        self.xp_progress_bar.setValue(int(progress['progress_percentage']))

        self.xp_progress_bar.setFormat(f"{progress['total_xp']:,} / {progress['next_level_xp']:,} XP")



        #3. Update Alert Feeds

        self.stats_labels['alerts'].setText(str(data['alerts_count']))

        self.update_alerts_display(data['recent_alerts'])



    def update_alerts_display(self, alerts ):

        """

        Re-render the list of alert widgets.

        

        Args:

            alerts(List[Dict]): List of alert objects from the db.

        """

        #clear existing widgets from layout

        while self.alerts_container.count():

            child =self.alerts_container.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



        if not alerts :

        #empty state

            no_alerts =QLabel("✓ No active threats detected. System secure.")

            no_alerts.setAlignment(Qt.AlignmentFlag.AlignCenter )

            no_alerts.setStyleSheet(f"color: {config.COLOR_SAFE}; font-weight: bold; padding: 20px;")

            self.alerts_container.addWidget(no_alerts )

            self.alerts_container.addStretch()

            return 



            #populate alerts

        for alert in alerts :

            alert_widget =self.create_alert_widget(alert )

            self.alerts_container.addWidget(alert_widget )



        self.alerts_container.addStretch()



    def create_alert_widget(self, alert :dict )->QWidget :

        """

        build a visual representation of a single security alert.

        

        Args:

            alert(dict): Alert data including type, severity, description.

            

        Returns:

            QWidget: Styled alert component.

        """

        frame =QFrame()

        frame.setFrameShape(QFrame.Shape.StyledPanel )



        #severity-based color mapping

        severity_colors ={

        'low':config.COLOR_SAFE ,

        'medium':config.COLOR_WARNING ,

        'high':config.COLOR_DANGER ,

        'critical':'#8B0000'

        }

        base_color =severity_colors.get(alert['severity'].lower(),config.COLOR_WARNING )



        #flat left edge to complement the accent border — avoids Qt corner clipping

        frame.setStyleSheet(f"""

            QFrame {{

                background-color: #fAFAFA;

                border: 1px solid #e0E0E0;

                border-left: 5px solid {base_color};

                border-top-left-radius: 0;

                border-bottom-left-radius: 0;

                border-top-right-radius: 6px;

                border-bottom-right-radius: 6px;

                padding: 12px;

            }}

            QFrame QLabel {{

                background: transparent;

            }}

        """)



        layout =QVBoxLayout()

        layout.setSpacing(4 )



        #header: Type & Severity

        header_text =f"⚠ {alert['alert_type'].replace('_', ' ').upper()} • {alert['severity'].upper()}"

        header =QLabel(header_text )

        header.setFont(QFont("Segoe UI",10, QFont.Weight.Bold ))

        header.setStyleSheet(f"color: {base_color};")



        #body: Description

        desc =QLabel(alert['description'])

        desc.setFont(QFont("Segoe UI",9 ))

        desc.setWordWrap(True )

        desc.setStyleSheet("color: #333;")



        #footer: Timestamp

        timestamp =QLabel(format_timestamp(alert['timestamp']))

        timestamp.setFont(QFont("Segoe UI",8 ))

        timestamp.setAlignment(Qt.AlignmentFlag.AlignRight )

        timestamp.setStyleSheet("color: #888;")



        layout.addWidget(header )

        layout.addWidget(desc )

        layout.addWidget(timestamp )



        frame.setLayout(layout )

        return frame 

