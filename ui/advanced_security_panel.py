import os 
from PyQt6.QtWidgets import(QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
QPushButton, QScrollArea, QWidget, QFrame )
from PyQt6.QtCore import Qt 
from PyQt6.QtGui import QFont, QIcon, QColor 

import config 
from ui.animated_toggle import AnimatedToggle 
from browser.security_settings import SecuritySettingsManager 

class AdvancedSecurityPanel(QDialog ):
    """
    Modal dialog providing fine-grained feature toggles extending the Chromium layer.
    """
    def __init__(self, settings_manager :SecuritySettingsManager, parent =None ):
        super().__init__(parent, Qt.WindowType.Dialog |Qt.WindowType.FramelessWindowHint )
        self.sm =settings_manager 

        #uI Styling
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {config.COLOR_SURFACE};
                border: 2px solid {config.COLOR_BORDER};
                border-radius: 12px;
            }}
            QLabel {{ color: {config.COLOR_TEXT}; }}
        """)
        self.setFixedSize(450, 600 )
        self.init_ui()
        self.populate_settings()

    def init_ui(self ):
        main_layout =QVBoxLayout(self )
        main_layout.setContentsMargins(20, 20, 20, 20 )
        main_layout.setSpacing(15 )

        #header
        header_hbox =QHBoxLayout()
        header_lbl =QLabel("🛡️ Advanced Profile Controls")
        header_lbl.setFont(QFont(config.FONT_FAMILY, 14, QFont.Weight.Bold ))
        header_lbl.setStyleSheet(f"color: {config.COLOR_PRIMARY};")

        self.btn_close =QPushButton("✕")
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor )
        self.btn_close.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent; border: none; font-size: 16px; color: {config.COLOR_SECONDARY};
            }}
            QPushButton:hover {{ color: {config.COLOR_DANGER}; }}
        """)
        self.btn_close.clicked.connect(self.accept )

        header_hbox.addWidget(header_lbl )
        header_hbox.addStretch()
        header_hbox.addWidget(self.btn_close )

        #content Scroll Area
        scroll_area =QScrollArea()
        scroll_area.setWidgetResizable(True )
        scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self.content_widget =QWidget()
        self.content_layout =QVBoxLayout(self.content_widget )
        self.content_layout.setContentsMargins(0, 0 ,0, 0 )
        self.content_layout.setSpacing(10 )
        scroll_area.setWidget(self.content_widget )

        #dynamic shield status
        self.shield_lbl =QLabel()
        self.shield_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter )
        self.shield_lbl.setFont(QFont(config.FONT_FAMILY, 12, QFont.Weight.Bold ))

        self.update_shield_ui()

        #footer
        footer_hbox =QHBoxLayout()

        self.btn_reset =QPushButton("Reset Defaults")
        self.btn_reset.setCursor(Qt.CursorShape.PointingHandCursor )
        self.btn_reset.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent; border: 1px solid {config.COLOR_BORDER};
                border-radius: 6px; padding: 6px 15px; color: {config.COLOR_TEXT};
            }}
            QPushButton:hover {{ background-color: {config.COLOR_BACKGROUND}; }}
        """)
        self.btn_reset.clicked.connect(self.reset_all )

        footer_hbox.addStretch()
        footer_hbox.addWidget(self.btn_reset )

        main_layout.addLayout(header_hbox )
        main_layout.addWidget(self.shield_lbl )
        main_layout.addWidget(scroll_area )
        main_layout.addLayout(footer_hbox )

    def populate_settings(self ):
        """build setting control rows mapped to internal data keys."""
        toggles =[
        ("Block JavaScript","Disable all page scripts. Highest security but blocks functionality.","block_js"),
        ("Block Popups / Windows","Prevent javascript window.open commands.","block_popups"),
        ("Disable Plugins","Turn off internal PDF viewer and Flash equivalents.","disable_plugins"),
        ("Disable Local Storage","Block HTML5 Storage preventing extensive offline tracking.","disable_local_storage"),
        ("Block Third-Party Cookies","Force NoPersistentCookies profile policy.","block_third_party_cookies"),
        ("Disable Screen Capture","Deny all WebRTC screen sharing payloads.","disable_screen_capture"),
        ("Block Automatic Downloads","Prevent executable dropping without explicit UI check.","block_auto_downloads"),
        ("Strict HTTPS Mode","Intercept HTTP routing and force SSL streams where valid.","strict_https"),
        ("Tracker Blocking Mode","Reject network calls hitting known Ad-Tech telemetry paths.","block_trackers")
        ]

        self.toggle_widgets ={}

        for title, desc, key in toggles :
            row =QFrame()
            row.setStyleSheet(f"background-color: {config.COLOR_BACKGROUND}; border-radius: 8px;")
            r_lay =QHBoxLayout(row )

            #label
            lbl_v =QVBoxLayout()
            title_lbl =QLabel(title )
            title_lbl.setFont(QFont(config.FONT_FAMILY, 11, QFont.Weight.Bold ))
            desc_lbl =QLabel(desc )
            desc_lbl.setStyleSheet(f"color: {config.COLOR_SECONDARY}; font-size: 10px;")
            desc_lbl.setWordWrap(True )

            lbl_v.addWidget(title_lbl )
            lbl_v.addWidget(desc_lbl )

            #switch
            switch =AnimatedToggle()
            switch.setChecked(self.sm.get(key ))

            #signal Closure trick Python 3 scoping
            def handle_toggle(checked, k =key ):
                self.sm.set(k, checked )
                self.update_shield_ui()

            switch.toggled.connect(handle_toggle )

            #map tracking references
            self.toggle_widgets[key ]=switch 

            r_lay.addLayout(lbl_v, 1 )
            r_lay.addWidget(switch )
            self.content_layout.addWidget(row )

        self.content_layout.addStretch()

    def update_shield_ui(self ):
        level =self.sm.determine_shield_level()
        color =config.COLOR_SAFE 
        if level =="Hardened":color =config.COLOR_WARNING 
        elif level =="Paranoid":color =config.COLOR_DANGER 

        self.shield_lbl.setText(f"Active Posture: {level}")
        self.shield_lbl.setStyleSheet(f"color: {color}; padding: 10px; border: 1px solid {color}; border-radius: 8px;")

    def reset_all(self ):
        for key, val in self.sm.DEFAULTS.items():
            if key in self.toggle_widgets :
                self.toggle_widgets[key ].setChecked(val )
