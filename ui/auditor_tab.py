"""

ML Model Auditor Interface.

    

Provides a suite of diagnostic tools for evaluating the health, security, 

and performance of deployed machine learning models. Features include 

drift detection, adversarial robustness testing, and integrity verification.

"""

from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QLabel, 

QPushButton, QTextEdit, QGroupBox, QProgressBar, QFrame, 

QScrollArea )

from PyQt6.QtCore import Qt, QThreadPool 

from PyQt6.QtGui import QFont 

from utils.workers import Worker 

import config 

from utils import format_file_size 





class AuditorTab(QWidget ):

    """

    Dashboard for the Model Auditor subsystem.

    

    Attributes:

        results_layout(QVBoxLayout): Container for dynamic audit reports.

    """



    def __init__(self, parent ):

        """setup the auditor UI and state."""

        super().__init__()

        self.parent =parent 

        self._is_auditing =False 

        self.init_ui()



    def init_ui(self ):

        """build the visual hierarchy of the audit dashboard."""

        layout =QVBoxLayout()

        layout.setSpacing(20 )



        #header

        title =QLabel("🔍 ML Model Auditor")

        title.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        layout.addWidget(title )



        #capability Description

        desc =QLabel("Monitor and audit machine learning models for drift, robustness, and performance. "

        "Ensures models remain accurate and secure over time.")

        desc.setWordWrap(True )

        desc.setStyleSheet("color: #666; font-size: 13px;")

        layout.addWidget(desc )



        #control Panel / Actions

        button_layout =QHBoxLayout()



        self._audit_phishing_btn =QPushButton("🔗 Audit Phishing Model")

        self._audit_phishing_btn.setToolTip("Run diagnostics on URL classification model")

        self._audit_phishing_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        self._audit_phishing_btn.clicked.connect(self.audit_phishing_model )



        self._audit_anomaly_btn =QPushButton("📊 Audit Anomaly Model")

        self._audit_anomaly_btn.setToolTip("Run diagnostics on log anomaly detection model")

        self._audit_anomaly_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        self._audit_anomaly_btn.clicked.connect(self.audit_anomaly_model )



        self._audit_all_btn =QPushButton("🔍 Full Audit Report")

        self._audit_all_btn.setToolTip("Execute comprehensive system-wide audit")

        self._audit_all_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        self._audit_all_btn.clicked.connect(self.audit_all_models )



        button_layout.addWidget(self._audit_phishing_btn )

        button_layout.addWidget(self._audit_anomaly_btn )

        button_layout.addWidget(self._audit_all_btn )



        self._retrain_btn =QPushButton("🔄 Retrain Models")

        self._retrain_btn.setToolTip("Delete and retrain both models on fresh synthetic data to resolve drift")

        self._retrain_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        self._retrain_btn.setStyleSheet(f"""

            QPushButton {{

                background-color: {config.COLOR_PRIMARY};

                color: white;

                font-weight: bold;

                border-radius: 6px;

                padding: 6px 14px;

            }}

            QPushButton:hover {{

                background-color: #2980b9;

            }}

        """)

        self._retrain_btn.clicked.connect(self._retrain_models )

        button_layout.addWidget(self._retrain_btn )



        layout.addLayout(button_layout )



        #reports Container — tall enough to show results without excessive scrolling

        self.results_group =QGroupBox("Audit Results")

        results_outer_layout =QVBoxLayout()



        scroll =QScrollArea()

        scroll.setWidgetResizable(True )

        scroll.setFrameShape(QFrame.Shape.NoFrame )



        results_container =QWidget()

        self.results_layout =QVBoxLayout(results_container )

        self.results_layout.setContentsMargins(0, 5 ,0, 5 )

        self.results_layout.setAlignment(Qt.AlignmentFlag.AlignTop )



        #initial State

        self.results_placeholder =QLabel("Select an audit target to begin analysis...")

        self.results_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.results_placeholder.setStyleSheet("color: #999; padding: 40px; font-style: italic;")

        self.results_layout.addWidget(self.results_placeholder )



        scroll.setWidget(results_container )

        results_outer_layout.addWidget(scroll )

        self.results_group.setLayout(results_outer_layout )

        self.results_group.setMinimumHeight(520 )



        layout.addWidget(self.results_group, 1 )#stretch = 1: fills remaining vertical space



        self.setLayout(layout )



    def _set_buttons_enabled(self, enabled :bool ):

        self._audit_phishing_btn.setEnabled(enabled )

        self._audit_anomaly_btn.setEnabled(enabled )

        self._audit_all_btn.setEnabled(enabled )

        self._retrain_btn.setEnabled(enabled )



    def _retrain_models(self ):

        """Force-retrain both ML models to resolve drift and refresh audit."""

        if self._is_auditing :

            return 

        self._is_auditing =True 

        self._set_buttons_enabled(False )

        self._show_loading("🔄 Retraining models, please wait...")



        def _do_retrain():

            import joblib 

            import config as _cfg 

            #retrain phishing model

            from detection.phishing_detector import PhishingDetector 

            pd =PhishingDetector()

            pd._train_model()#forces fresh synthetic retrain and saves

            #retrain anomaly model

            from detection.anomaly_detector import AnomalyDetector 

            ad =AnomalyDetector()

            ad._train_model()

            #reload auditor references

            return "retrain_done"



        worker =Worker(_do_retrain )

        worker.signals.result.connect(self._on_retrain_done )

        worker.signals.error.connect(self._on_audit_error )

        QThreadPool.globalInstance().start(worker )



    def _on_retrain_done(self, _result ):

        """After retrain, reload auditor model references and run a full audit."""

        try :

            self.parent.auditor._load_models()

        except Exception :

            pass 

        self._is_auditing =False 

        self._set_buttons_enabled(True )

        self._stop_loading()

        self.clear_results()

        ok_lbl =QLabel("✅ Models retrained successfully. Running fresh audit...")

        ok_lbl.setStyleSheet(f"color: {config.COLOR_SAFE}; font-weight: bold; padding: 10px;")

        self.results_layout.addWidget(ok_lbl )

        #trigger full audit automatically

        self.audit_all_models()



    def _show_loading(self, message :str ):

        """Display a transient loading indicator in the results panel."""

        self.clear_results()

        self.loading_label =QLabel(message )

        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.loading_label.setStyleSheet("color: #666; padding: 40px; font-style: italic;")

        self.results_layout.addWidget(self.loading_label )



        from ui.animations import LoadingAnimation 

        self.loading_anim =LoadingAnimation(self.loading_label.setText, message.replace("...",""))

        self.loading_anim.start()



    def _stop_loading(self ):

        if hasattr(self ,'loading_anim'):

            self.loading_anim.stop()



    def audit_phishing_model(self ):

        """

        runs audit workflow for the Phishing Classification Model asynchronously.

        """

        if self._is_auditing :

            return 

        self._is_auditing =True 

        self._set_buttons_enabled(False )

        self._show_loading("🔍 Running phishing model audit, please wait...")

        worker =Worker(self.parent.auditor.audit_phishing_model )

        worker.signals.result.connect(self._on_phishing_result )

        worker.signals.error.connect(self._on_audit_error )

        QThreadPool.globalInstance().start(worker )



    def audit_anomaly_model(self ):

        """

        runs audit workflow for the Anomaly Detection Model asynchronously.

        """

        if self._is_auditing :

            return 

        self._is_auditing =True 

        self._set_buttons_enabled(False )

        self._show_loading("📊 Running anomaly model audit, please wait...")

        worker =Worker(self.parent.auditor.audit_anomaly_model )

        worker.signals.result.connect(self._on_anomaly_result )

        worker.signals.error.connect(self._on_audit_error )

        QThreadPool.globalInstance().start(worker )



    def audit_all_models(self ):

        """

        runs audit workflows for all registered models asynchronously.

        """

        if self._is_auditing :

            return 

        self._is_auditing =True 

        self._set_buttons_enabled(False )

        self._show_loading("🔍 Running full system audit, please wait...")

        worker =Worker(self.parent.auditor.get_full_audit_report )

        worker.signals.result.connect(self._handle_full_audit_result )

        worker.signals.error.connect(self._on_audit_error )

        QThreadPool.globalInstance().start(worker )



    def _on_phishing_result(self, result :dict ):

        self._handle_audit_result(result ,"Phishing Detection Model")



    def _on_anomaly_result(self, result :dict ):

        self._handle_audit_result(result ,"Anomaly Detection Model")



    def _on_audit_error(self, err :tuple ):

        self._stop_loading()

        self._is_auditing =False 

        self._set_buttons_enabled(True )

        self.display_error(str(err[1 ]))



    def _handle_audit_result(self, result :dict, model_name :str ):

        """Render a single model audit result after async completion."""

        self._stop_loading()

        self._is_auditing =False 

        self._set_buttons_enabled(True )

        self.clear_results()

        if 'error'in result :

            self.display_error(result['error'])

        else :

            self.display_model_audit(result, model_name )



    def _handle_full_audit_result(self, report :dict ):

        """Render the combined full audit report after async completion."""

        self._stop_loading()

        self._is_auditing =False 

        self._set_buttons_enabled(True )

        self.clear_results()



        phishing_report =report.get('phishing_model')

        if phishing_report and 'error'not in phishing_report :

            self.display_model_audit(phishing_report ,"Phishing Detection Model")



        anomaly_report =report.get('anomaly_model')

        if anomaly_report and 'error'not in anomaly_report :

            self.display_model_audit(anomaly_report ,"Anomaly Detection Model")



    def clear_results(self ):

        """Reset the results view."""

        while self.results_layout.count():

            child =self.results_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



    def display_error(self, error_msg :str ):

        """Render error feedback."""

        error_label =QLabel(f"❌ Audit Failed: {error_msg}")

        error_label.setStyleSheet(f"color: {config.COLOR_DANGER}; font-weight: bold; padding: 20px;")

        error_label.setWordWrap(True )

        self.results_layout.addWidget(error_label )



    def display_model_audit(self, result :dict, model_name :str ):

        """

        Render the comprehensive audit report for a single model.

        

        Args:

            result(dict): Audit metrics and test results.

            model_name(str): Display name of the model.

        """

        #1. Health Scorecard

        health_card =self.create_health_card(result, model_name )

        self.results_layout.addWidget(health_card )



        #2. Model Specifications

        metadata_widget =self.create_metadata_widget(result )

        self.results_layout.addWidget(metadata_widget )



        #3. Drift Analysis

        drift_widget =self.create_drift_widget(result )

        self.results_layout.addWidget(drift_widget )



        #4. Adversarial Robustness(if applicable)

        if 'robustness_test'in result :

            robustness_widget =self.create_robustness_widget(result )

            self.results_layout.addWidget(robustness_widget )



    def create_health_card(self, result :dict, model_name :str )->QWidget :

        """

        build a visual scorecard indicating overall model health.

        """

        health_score =result['health_score']



        #determine status tiers

        if health_score >=80 :

            color =config.COLOR_SAFE 

            status ="HEALTHY"

        elif health_score >=50 :

            color =config.COLOR_WARNING 

            status ="WARNING"

        else :

            color =config.COLOR_DANGER 

            status ="CRITICAL"



        frame =QFrame()

        frame.setFrameShape(QFrame.Shape.StyledPanel )

        frame.setStyleSheet(f"""

            QFrame {{

                background-color: {color};

                border-radius: 12px;

                padding: 24px;

            }}

            QLabel {{

                color: white;

            }}

        """)



        layout =QVBoxLayout()



        #title

        name_label =QLabel(model_name )

        name_label.setFont(QFont("Segoe UI",18, QFont.Weight.Bold ))

        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter )



        #status Text

        status_label =QLabel(f"{status} - Health Score: {health_score}/100")

        status_label.setFont(QFont("Segoe UI",14 ))

        status_label.setAlignment(Qt.AlignmentFlag.AlignCenter )



        #visual Progress Bar

        progress =QProgressBar()

        progress.setValue(health_score )

        progress.setTextVisible(False )

        progress.setStyleSheet(f"""

            QProgressBar {{

                border: 2px solid white;

                border-radius: 6px;

                background-color: rgba(255, 255, 255, 0.3);

                height: 12px;

            }}

            QProgressBar::chunk {{

                background-color: white;

                border-radius: 4px;

            }}

        """)



        layout.addWidget(name_label )

        layout.addWidget(status_label )

        layout.addWidget(progress )



        frame.setLayout(layout )

        return frame 



    def create_metadata_widget(self, result :dict )->QWidget :

        """

        Render technical specifications of the model.

        """

        group =QGroupBox("Model Metadata")

        layout =QVBoxLayout()



        metadata =result.get('metadata',{})



        info_text =f"<b>Model Type:</b> {result.get('model_type', 'Unknown')}<br>"

        info_text +=f"<b>File:</b> {metadata.get('model_file', 'N/A')}<br>"

        info_text +=f"<b>File Size:</b> {format_file_size(int(metadata.get('file_size_kb', 0) * 1024))}<br>"



        if 'n_estimators'in metadata :

            info_text +=f"<b>Estimators:</b> {metadata['n_estimators']}<br>"

        if 'max_depth'in metadata :

            info_text +=f"<b>Max Depth:</b> {metadata['max_depth']}<br>"



        info_label =QLabel(info_text )

        info_label.setStyleSheet("font-size: 13px; line-height: 1.4;")

        layout.addWidget(info_label )



        group.setLayout(layout )

        return group 



    def create_drift_widget(self, result :dict )->QWidget :

        """

        Render drift detection analysis results.

        """

        group =QGroupBox("Drift Analysis")

        layout =QVBoxLayout()



        drift_analysis =result.get('drift_analysis',{})



        #summary

        drift_detected =drift_analysis.get('drift_detected',False )



        if drift_detected :

            summary =QLabel("⚠ Drift Detected - Model may need retraining")

            summary.setStyleSheet(f"color: {config.COLOR_WARNING}; font-weight: bold; font-size: 14px;")

        else :

            summary =QLabel("✓ No Drift Detected - Model is stable")

            summary.setStyleSheet(f"color: {config.COLOR_SAFE}; font-weight: bold; font-size: 14px;")



        layout.addWidget(summary )



        #method Details

        method_label =QLabel(f"<b>Test Method:</b> {drift_analysis.get('test_method', 'N/A')}")

        layout.addWidget(method_label )



        #actionable Recommendation

        recommendation =QLabel(f"<b>Recommendation:</b> {drift_analysis.get('recommendation', 'N/A')}")

        layout.addWidget(recommendation )



        #feature-level Breakdown

        feature_drifts =drift_analysis.get('feature_drifts',[])

        if feature_drifts :

            drifted_features =[f for f in feature_drifts if f['drift_detected']]

            if drifted_features :

                drift_text =f"<b>Drifted Features:</b> {len(drifted_features)} out of {len(feature_drifts)}"

                drift_label =QLabel(drift_text )

                layout.addWidget(drift_label )



        group.setLayout(layout )

        return group 



    def create_robustness_widget(self, result :dict )->QWidget :

        """

        Render adversarial robustness test results.

        """

        group =QGroupBox("Adversarial Robustness Test")

        layout =QVBoxLayout()



        robustness =result.get('robustness_test',{})



        #overall Assessment

        vulnerability_score =robustness.get('vulnerability_score',0 )

        assessment =robustness.get('assessment','Unknown')



        if vulnerability_score <0.3 :

            color =config.COLOR_SAFE 

        else :

            color =config.COLOR_WARNING 



        assessment_label =QLabel(f"<b>Assessment:</b> {assessment}")

        assessment_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 14px;")

        layout.addWidget(assessment_label )



        #quantitative Metric

        vuln_label =QLabel(f"<b>Vulnerability Score:</b> {vulnerability_score:.2%}")

        layout.addWidget(vuln_label )



        #detailed Perturbation Analysis

        test_results =robustness.get('test_results',[])

        if test_results :

            results_text ="<b>Perturbation Tests:</b><br>"

            for test in test_results :

                results_text +=f"• ε={test['perturbation']}: {test['flip_rate']:.1%} prediction changes<br>"



            results_label =QLabel(results_text )

            results_label.setStyleSheet("font-size: 13px; line-height: 1.4;")

            layout.addWidget(results_label )



        group.setLayout(layout )

        return group 

