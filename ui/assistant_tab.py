"""

Security Intelligence Assistant Interface.

    

Provides an interactive natural language interface for querying the 

knowledge base. Supports RAG(Retrieval-Augmented Generation) to ground 

answers in verified security documentation(MITRE ATT&CK, OWASP).

"""

from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QLabel, 

QLineEdit, QPushButton, QTextEdit, QGroupBox, QScrollArea, QSizePolicy, QSpacerItem )

from PyQt6.QtCore import Qt, QThreadPool, QPoint, QTimer 

from PyQt6.QtGui import QFont 

from utils.workers import Worker 

import config 

from ui.animations import fade_in, slide_and_fade, animate_scroll, LoadingAnimation 





class AssistantTab(QWidget ):

    """

    RAG-powered conversational interface.

    

    Attributes:

        chat_display(QTextEdit): Read-only view for conversation history.

        question_input(QLineEdit): User prompt entry field.

    """



    def __init__(self, parent ):

        """setup the assistant UI and state."""

        super().__init__()

        self.parent =parent 

        self.chat_history =[]

        self._temp_block_start =0 

        self._is_querying =False 

        self.init_ui()



    def init_ui(self ):

        """build the visual hierarchy of the chat interface."""

        layout =QVBoxLayout()

        layout.setSpacing(20 )



        #header

        title =QLabel("🤖 AI Security Assistant")

        title.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        layout.addWidget(title )



        #capability Description

        desc =QLabel("Ask questions about cybersecurity threats, best practices, and remediation steps. "

        "Powered by local RAG with MITRE ATT&CK and OWASP knowledge base.")

        desc.setWordWrap(True )

        desc.setStyleSheet("color: #666; font-size: 13px;")

        layout.addWidget(desc )



        #suggested Actions / Quick Prompts

        quick_group =QGroupBox("Suggested Topics")

        quick_layout =QVBoxLayout()



        quick_buttons_layout =QHBoxLayout()



        questions =[

        ("What is phishing?","Define phishing and common indicators."),

        ("SQL Injection","How does SQL injection work and how to prevent it?"),

        ("Brute Force","Explain brute force attacks and mitigation strategies."),

        ("Ransomware","What are the first steps to take during a ransomware infection?")

        ]



        for btn_text, question in questions :

            btn =QPushButton(btn_text )

            btn.setCursor(Qt.CursorShape.PointingHandCursor )

            btn.setToolTip(f"Ask: {question}")

            btn.clicked.connect(lambda checked, q =question :self.ask_question(q ))

            quick_buttons_layout.addWidget(btn )



        quick_layout.addLayout(quick_buttons_layout )

        quick_group.setLayout(quick_layout )

        layout.addWidget(quick_group )



        #conversation Container

        chat_group =QGroupBox("Live Session")

        chat_layout =QVBoxLayout()



        #transcript View

        self.chat_scroll =QScrollArea()

        self.chat_scroll.setWidgetResizable(True )

        self.chat_scroll.setMinimumHeight(300 )

        self.chat_scroll.setStyleSheet("""

            QScrollArea {

                background-color: #fAFAFA;

                border: 1px solid #e0E0E0;

                border-radius: 6px;

            }

            QWidget#chat_container {

                background-color: transparent;

            }

        """)



        self.chat_container =QWidget()

        self.chat_container.setObjectName("chat_container")

        self.chat_layout =QVBoxLayout(self.chat_container )

        self.chat_layout.setAlignment(Qt.AlignmentFlag.AlignTop )

        self.chat_layout.setSpacing(10 )



        self.chat_scroll.setWidget(self.chat_container )

        chat_layout.addWidget(self.chat_scroll )



        #input Controls

        input_layout =QHBoxLayout()



        self.question_input =QLineEdit()

        self.question_input.setPlaceholderText("Type your security question here...")

        self.question_input.returnPressed.connect(self.submit_question )



        self._ask_btn =QPushButton("Send Query")

        self._ask_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        self._ask_btn.clicked.connect(self.submit_question )



        clear_btn =QPushButton("Clear Session")

        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        clear_btn.setStyleSheet(f"""

            QPushButton {{

                background-color: transparent;

                color: #888;

                border: 1px solid #ddd;

            }}

            QPushButton:hover {{

                background-color: #f0f0f0;

                color: {config.COLOR_DANGER};

                border: 1px solid {config.COLOR_DANGER};

            }}

        """)

        clear_btn.clicked.connect(self.clear_chat )



        input_layout.addWidget(self.question_input, 4 )

        input_layout.addWidget(self._ask_btn, 1 )

        input_layout.addWidget(clear_btn, 0 )



        chat_layout.addLayout(input_layout )

        chat_group.setLayout(chat_layout )

        layout.addWidget(chat_group )



        self.setLayout(layout )



        #initial greeting

        self.add_message("assistant","👋 Hello! I'm your AI Security Assistant. How can I help secure your environment today?")



    def ask_question(self, question :str ):

        """

        Trigger a specific query from UI shortcuts.

        """

        self.question_input.setText(question )

        self.submit_question()



    def submit_question(self ):

        """

        Process the user's input asynchronously.

        """

        if self._is_querying :

            return 



        question =self.question_input.text().strip()

        if not question :

            return 



        self._is_querying =True 

        self._ask_btn.setEnabled(False )

        self.question_input.setEnabled(False )



        #1. User Message

        self.add_message("user",question )

        self.question_input.clear()



        #add typing indicator

        self.loading_widget =self._create_bubble("assistant","Typing...")

        self.loading_anim =LoadingAnimation(self._update_loading_text ,"Typing...")

        self.loading_anim.start()



        #2. Inference via Worker

        worker =Worker(self.parent.assistant.query, question )

        worker.signals.result.connect(self._handle_response )

        worker.signals.error.connect(self._on_worker_error )

        QThreadPool.globalInstance().start(worker )



    def _on_worker_error(self, err :tuple ):

        self._is_querying =False 

        self._ask_btn.setEnabled(True )

        self.question_input.setEnabled(True )

        self.question_input.setFocus()

        self._handle_response({'success':False ,'answer':f"System Error: {err[1]}"})



    def _handle_response(self, result :dict ):

        """Display the Worker's RAG response."""

        self._is_querying =False 

        self._ask_btn.setEnabled(True )

        self.question_input.setEnabled(True )

        self.question_input.setFocus()



        #remove typing indicator

        if hasattr(self ,'loading_anim')and self.loading_anim :

            self.loading_anim.stop()

            self.loading_anim =None 



            #guard: loading_widget may be None if clear_chat() was called during

            #the in-flight query. Skip widget removal gracefully in that case

        if hasattr(self ,'loading_widget')and self.loading_widget is not None :

            try :

                self.chat_layout.removeWidget(self.loading_widget )

                self.loading_widget.deleteLater()

            except RuntimeError :

                pass 

            self.loading_widget =None 



            #3. Response Rendering

        if result.get('success',False ):

            sources_html =""

            #format Citations / Sources safely for addition into the bubble

            if result.get('sources'):

                sources_html ="<div style='font-size: 11px; color: #666; border-top: 1px solid #eee; padding-top: 5px; margin-top: 10px;'>"

                sources_html +="<b>📚 Reference Knowledge:</b><ul style='margin-top: 0; padding-left: 15px;'>"

                for source in result['sources'][:3 ]:

                    sources_html +=f"<li>{source.get('topic', 'Unknown')} ({source.get('category', 'Docs')})</li>"

                sources_html +="</ul></div>"



            self.add_message("assistant",result['answer'],sources_html =sources_html )

        else :

            self.add_message("assistant",f"❌ System Error: {result.get('answer', 'Unknown execution error')}")



    def _update_loading_text(self, text ):

        if hasattr(self ,'loading_widget')and self.loading_widget :

            try :

                lbl =self.loading_widget.findChild(QLabel )

                if lbl :

                    lbl.setText(f"<b>🤖 Assistant</b><br>{text}")

            except RuntimeError :

                pass 



    def _create_bubble(self, sender :str, message :str, sources_html :str =""):

    #sanitize literal computer-code artifacts

        message =str(message ).replace('\\n','\n')



        container =QWidget()

        layout =QHBoxLayout(container )

        layout.setContentsMargins(0, 0 ,0, 0 )



        label =QLabel()

        label.setWordWrap(True )

        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse )

        label.setTextFormat(Qt.TextFormat.MarkdownText )



        if sender =="user":

            label.setStyleSheet(f"""

                QLabel {{

                    background-color: {config.COLOR_PRIMARY};

                    color: white;

                    padding: 12px;

                    border-radius: 12px 12px 0 12px;

                    font-family: "Segoe UI";

                    font-size: 13px;

                }}

            """)

            label.setText(f"**You**\n\n{message}")

            #align right

            layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum ))

            layout.addWidget(label )

        else :

            label.setStyleSheet("""

                QLabel {

                    background-color: white; 

                    border: 1px solid #e0E0E0;

                    color: #333;

                    padding: 12px; 

                    border-radius: 12px 12px 12px 0;

                    font-family: "Segoe UI";

                    font-size: 13px;

                }

            """)



            #combine Markdown message with HTML sources(Qt will render both if combined intelligently)

            label.setText(f"**🤖 Assistant**\n\n{message}\n\n{sources_html}")

            #align left

            layout.addWidget(label )

            layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum ))



        self.chat_layout.addWidget(container )



        #smooth auto-scroll using animation after layout happens

        QTimer.singleShot(50, self._scroll_to_bottom )



        return container 



    def add_message(self, sender :str, message :str, sources_html :str ="",is_temp :bool =False ):

        """Render a chat bubble in the transcript."""

        if not is_temp :

            self.chat_history.append({'sender':sender ,'message':message })



        container =self._create_bubble(sender, message, sources_html )



        #animate Slide & Fade In

        QTimer.singleShot(10, lambda :self._apply_slide_anim(container, sender ))



    def _apply_slide_anim(self, container, sender ):

        end_pos =container.pos()

        offset =QPoint(50, 0 )if sender =="user"else QPoint(-50, 0 )

        start_pos =end_pos +offset 

        slide_and_fade(container, start_pos, end_pos, 300 )



    def _scroll_to_bottom(self ):

        scrollbar =self.chat_scroll.verticalScrollBar()

        animate_scroll(scrollbar, scrollbar.maximum())



    def clear_chat(self ):

        """Reset the conversation context.

        

        Safely handles the case where a query worker is still in-flight:

        resets the _is_querying guard and re-enables input controls so the

        UI is not permanently locked after a clear-during-query operation.

        """

        self.chat_history =[]



        #stop and discard any active typing animation

        if hasattr(self ,'loading_anim')and self.loading_anim :

            self.loading_anim.stop()

            self.loading_anim =None 



            #discard the loading widget reference before clearing the layout

            #so that the incoming worker result(if any) silently no-ops

        self.loading_widget =None 



        #reset the in-flight query guard and re-enable user controls

        #this prevents the assistant being permanently locked if the user

        #clears chat while a RAG query worker is still running

        self._is_querying =False 

        self._ask_btn.setEnabled(True )

        self.question_input.setEnabled(True )



        #remove all widgets from layout

        while self.chat_layout.count():

            item =self.chat_layout.takeAt(0 )

            if item.widget():

                try :

                    item.widget().deleteLater()

                except RuntimeError :

                    pass 



        self.add_message("assistant","Session cleared. Ready for new queries.")

