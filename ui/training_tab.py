"""

Security Awareness Training Interface.

    

adds a gamified learning environment to reinforce cybersecurity 

best practices. Features interactive assessments, progress tracking 

(XP/Leveling), and immediate feedback mechanisms.

"""

from PyQt6.QtWidgets import(QWidget, QVBoxLayout, QHBoxLayout, QLabel, 

QPushButton, QRadioButton, QButtonGroup, QGroupBox, 

QProgressBar, QFrame, QTextEdit )

from PyQt6.QtCore import Qt 

from PyQt6.QtGui import QFont 

import config 





class TrainingTab(QWidget ):

    """

    User interface for the Gamification/Training subsystem.

    

    Attributes:

        quiz_layout(QVBoxLayout): Dynamic container for quiz questions and results.

        progress_bar(QProgressBar): Visual indicator of level progression.

    """



    def __init__(self, parent ):

        """setup the training UI and session state."""

        super().__init__()

        self.parent =parent 

        self.current_quiz =[]

        self.current_question_index =0 

        self.init_ui()



    def init_ui(self ):

        """build the visual hierarchy of the training dashboard."""

        layout =QVBoxLayout()

        layout.setSpacing(20 )



        #header

        title =QLabel("🎓 Security Awareness Training")

        title.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        layout.addWidget(title )



        #description

        desc =QLabel("Test your cybersecurity knowledge and earn XP! "

        "Complete quizzes to level up and improve your security awareness.")

        desc.setWordWrap(True )

        desc.setStyleSheet("color: #666; font-size: 13px;")

        layout.addWidget(desc )



        #user Stats / Progress Bar

        progress_group =self.create_progress_section()

        layout.addWidget(progress_group )



        #active Quiz Container

        self.quiz_group =QGroupBox("Active Session")

        self.quiz_layout =QVBoxLayout()



        #initial State: Start Screen

        self.show_start_screen()



        self.quiz_group.setLayout(self.quiz_layout )

        layout.addWidget(self.quiz_group )



        layout.addStretch()

        self.setLayout(layout )



    def create_progress_section(self )->QWidget :

        """

        build the user progress tracking section.

        """

        group =QGroupBox("Career Progression")

        layout =QVBoxLayout()



        #statistics Grid

        stats_layout =QHBoxLayout()



        #current Level

        self.level_label =QLabel("Level: --")

        self.level_label.setFont(QFont("Segoe UI",16, QFont.Weight.Bold ))

        self.level_label.setStyleSheet(f"color: {config.COLOR_PRIMARY};")



        #total Experience Points

        self.xp_label =QLabel("XP: --")

        self.xp_label.setFont(QFont("Segoe UI",14 ))



        #modules Completed

        self.quizzes_label =QLabel("Quizzes: --")

        self.quizzes_label.setFont(QFont("Segoe UI",14 ))



        stats_layout.addWidget(self.level_label )

        stats_layout.addWidget(self.xp_label )

        stats_layout.addWidget(self.quizzes_label )

        stats_layout.addStretch()



        layout.addLayout(stats_layout )



        #visual Progress Indicator

        progress_label =QLabel("Next Level Progress:")

        progress_label.setStyleSheet("font-weight: bold; margin-top: 10px;")

        layout.addWidget(progress_label )



        self.progress_bar =QProgressBar()

        self.progress_bar.setStyleSheet(f"""

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

        layout.addWidget(self.progress_bar )



        group.setLayout(layout )



        #hydrate with initial data

        self.update_progress()



        return group 



    def update_progress(self ):

        """Fetch and display latest user statistics."""

        stats =self.parent.gamification.get_user_stats()



        self.level_label.setText(f"Level: {stats['level']}")

        self.xp_label.setText(f"XP: {stats['total_xp']}")

        self.quizzes_label.setText(f"Quizzes: {stats['quizzes_completed']}")

        self.progress_bar.setValue(int(stats['progress_percentage']))



    def show_start_screen(self ):

        """Render the quiz initiation screen."""

        self.clear_quiz_layout()



        #call to Action

        welcome =QLabel("Ready to test your security knowledge?")

        welcome.setFont(QFont("Segoe UI",16 ))

        welcome.setAlignment(Qt.AlignmentFlag.AlignCenter )

        self.quiz_layout.addWidget(welcome )



        #incentive Information

        info =QLabel(f"• Earn {config.XP_PER_QUIZ} XP for correct answers\n"

        "• Master key concepts through detailed feedback\n"

        "• Climb the ranks from Novice to Expert")

        info.setAlignment(Qt.AlignmentFlag.AlignCenter )

        info.setStyleSheet("color: #666; padding: 20px; line-height: 1.6;")

        self.quiz_layout.addWidget(info )



        #launch Button

        start_btn =QPushButton("🎯 Start Assessment(5 Questions)")

        start_btn.setMinimumHeight(45 )

        start_btn.setFont(QFont("Segoe UI",12, QFont.Weight.Bold ))

        start_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        start_btn.clicked.connect(self.start_quiz )

        self.quiz_layout.addWidget(start_btn )



    def clear_quiz_layout(self ):

        """Remove all widgets from the active quiz container."""

        while self.quiz_layout.count():

            child =self.quiz_layout.takeAt(0 )

            if child.widget():

                child.widget().deleteLater()



    def start_quiz(self ):

        """

        setup a new training session.

        

        1. Selects random questions from the pool.

        2. Resets state.

        3. Displays the first question.

        """

        self.current_quiz =self.parent.gamification.get_random_quiz(5 )

        self.current_question_index =0 

        self.show_question()



    def show_question(self ):

        """Render the current question interface."""

        if self.current_question_index >=len(self.current_quiz ):

            self.show_quiz_complete()

            return 



        self.clear_quiz_layout()



        question =self.current_quiz[self.current_question_index ]



        #progress Counter

        progress_label =QLabel(f"Question {self.current_question_index + 1} of {len(self.current_quiz)}")

        progress_label.setFont(QFont("Segoe UI",11, QFont.Weight.Bold ))

        progress_label.setStyleSheet(f"color: {config.COLOR_PRIMARY};")

        self.quiz_layout.addWidget(progress_label )



        #question Text

        question_label =QLabel(question['question'])

        question_label.setFont(QFont("Segoe UI",14, QFont.Weight.Bold ))

        question_label.setWordWrap(True )

        question_label.setStyleSheet("padding: 15px 10px; color: #2c3e50; margin-bottom: 10px;")

        question_label.setMinimumHeight(60 )

        self.quiz_layout.addWidget(question_label )



        #options List

        self.option_group =QButtonGroup()



        for i, option in enumerate(question['options']):

            radio =QRadioButton(option )

            radio.setFont(QFont("Segoe UI",12 ))

            radio.setStyleSheet("""

                QRadioButton {

                    padding: 10px;

                    color: #2c3e50;

                    spacing: 8px;

                }

                QRadioButton::indicator {

                    width: 18px;

                    height: 18px;

                }

            """)

            radio.setCursor(Qt.CursorShape.PointingHandCursor )

            self.option_group.addButton(radio, i )

            self.quiz_layout.addWidget(radio )



            #submission Control

        submit_btn =QPushButton("Submit Answer")

        submit_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        submit_btn.clicked.connect(lambda :self.check_answer(question ))

        self.quiz_layout.addWidget(submit_btn )



    def check_answer(self, question :dict ):

        """

        check user selection and process results.

        

        Args:

            question(dict): The current question object.

        """

        selected_id =self.option_group.checkedId()



        if selected_id ==-1 :

            return #no option selected



        result =self.parent.gamification.check_answer(question['id'],selected_id )



        self.show_answer_feedback(question, selected_id, result )



        #update Stats immediately

        self.update_progress()



    def show_answer_feedback(self, question :dict, selected :int, result :dict ):

        """

        Render immediate feedback for the last answer.

        """

        self.clear_quiz_layout()



        #feedback Card Styling

        if result['correct']:

            color =config.COLOR_SAFE 

            icon ="✓"

            title ="Correct!"

            bg_color =config.COLOR_SAFE 

        else :

            color =config.COLOR_DANGER 

            icon ="✗"

            title ="Incorrect"

            bg_color =config.COLOR_DANGER 



        result_frame =QFrame()

        result_frame.setFrameShape(QFrame.Shape.StyledPanel )

        result_frame.setStyleSheet(f"""

            QFrame {{

                background-color: {bg_color};

                border-radius: 12px;

                padding: 24px;

            }}

            QLabel {{

                color: white;

            }}

        """)



        result_layout =QVBoxLayout()



        result_title =QLabel(f"{icon} {title}")

        result_title.setFont(QFont("Segoe UI",20, QFont.Weight.Bold ))

        result_title.setAlignment(Qt.AlignmentFlag.AlignCenter )



        result_layout.addWidget(result_title )



        if result['xp_earned']>0 :

            xp_label =QLabel(f"+{result['xp_earned']} XP")

            xp_label.setFont(QFont("Segoe UI",16 ))

            xp_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

            result_layout.addWidget(xp_label )



        if result.get('level_up'):

            level_up_label =QLabel("🎉 LEVEL UP! 🎉")

            level_up_label.setFont(QFont("Segoe UI",18, QFont.Weight.Bold ))

            level_up_label.setAlignment(Qt.AlignmentFlag.AlignCenter )

            result_layout.addWidget(level_up_label )



        result_frame.setLayout(result_layout )

        self.quiz_layout.addWidget(result_frame )



        #show Correct Answer(Learning Moment)

        if not result['correct']:

            correct_label =QLabel(f"<b>Correct Answer:</b> {result['correct_answer']}")

            correct_label.setWordWrap(True )

            correct_label.setStyleSheet(f"padding: 15px; font-size: 14px; color: {config.COLOR_DANGER}; background: #FFF5F5; border-radius: 6px;")

            self.quiz_layout.addWidget(correct_label )



            #detailed Explanation — bounded height so Next button stays visible

        explanation_group =QGroupBox("Explanation")

        explanation_layout =QVBoxLayout()



        explanation_edit =QTextEdit()

        explanation_edit.setReadOnly(True )

        explanation_edit.setPlainText(result['explanation'])

        explanation_edit.setMaximumHeight(120 )

        explanation_edit.setStyleSheet("""

            QTextEdit {

                font-size: 13px;

                background: transparent;

                border: none;

                padding: 0;

            }

        """)

        explanation_layout.addWidget(explanation_edit )



        explanation_group.setLayout(explanation_layout )

        self.quiz_layout.addWidget(explanation_group )



        #navigation

        next_btn =QPushButton("Next Question →")

        next_btn.setMinimumHeight(40 )

        next_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        next_btn.clicked.connect(self.next_question )

        self.quiz_layout.addWidget(next_btn )



    def next_question(self ):

        """Advance the quiz state."""

        self.current_question_index +=1 

        self.show_question()



    def show_quiz_complete(self ):

        """Display the session summary."""

        self.clear_quiz_layout()



        #completion Card

        complete_frame =QFrame()

        complete_frame.setFrameShape(QFrame.Shape.StyledPanel )

        complete_frame.setStyleSheet(f"""

            QFrame {{

                background-color: {config.COLOR_PRIMARY};

                border-radius: 12px;

                padding: 30px;

            }}

            QLabel {{

                color: white;

            }}

        """)



        complete_layout =QVBoxLayout()



        title =QLabel("🎉 Assessment Complete!")

        title.setFont(QFont("Segoe UI",24, QFont.Weight.Bold ))

        title.setAlignment(Qt.AlignmentFlag.AlignCenter )



        message =QLabel("Great job reinforcing your security knowledge.")

        message.setFont(QFont("Segoe UI",14 ))

        message.setAlignment(Qt.AlignmentFlag.AlignCenter )



        complete_layout.addWidget(title )

        complete_layout.addWidget(message )



        complete_frame.setLayout(complete_layout )

        self.quiz_layout.addWidget(complete_frame )



        #actions

        button_layout =QHBoxLayout()



        restart_btn =QPushButton("🔄 Retake Quiz")

        restart_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        restart_btn.clicked.connect(self.start_quiz )



        home_btn =QPushButton("🏠 Dashboard")

        home_btn.setCursor(Qt.CursorShape.PointingHandCursor )

        home_btn.clicked.connect(self.show_start_screen )



        button_layout.addWidget(restart_btn )

        button_layout.addWidget(home_btn )



        self.quiz_layout.addLayout(button_layout )

