"""

Gamification system for security awareness training

Includes quizzes and XP tracking

"""

import random 

from typing import Dict, List 

from PyQt6.QtCore import QObject, pyqtSignal 

from database import DatabaseManager 





class GamificationManager(QObject ):

    """Manages gamification features including quizzes and XP"""



    xp_updated =pyqtSignal()



    def __init__(self, db_manager :DatabaseManager ):

        super().__init__()

        self.db =db_manager 

        self.quiz_bank =self._create_quiz_bank()



    def _create_quiz_bank(self )->List[Dict ]:

        """Create phishing awareness quiz bank"""

        return[

        {

        'id':1 ,

        'question':'Which of these is a common sign of a phishing email?',

        'options':[

        'Professional logo and formatting',

        'Urgent request for password reset',

        'Personalized greeting with your name',

        'Email from known contact'

        ],

        'correct':1 ,

        'explanation':'Phishing emails often create urgency to pressure victims into acting without thinking.'

        },

        {

        'id':2 ,

        'question':'What should you check first when receiving a suspicious link?',

        'options':[

        'Click it to see where it goes',

        'Hover over it to see the actual URL',

        'Forward it to friends for verification',

        'Reply asking if it\'s legitimate'

        ],

        'correct':1 ,

        'explanation':'Always hover over links to reveal the true destination before clicking.'

        },

        {

        'id':3 ,

        'question':'Which URL is most likely to be a phishing attempt?',

        'options':[

        'https://www.paypal.com/login',

        'https://paypa1.com/verify-account',

        'https://secure.paypal.com',

        'https://www.paypal.com/security'

        ],

        'correct':1 ,

        'explanation':'Notice the "1" instead of "l" in paypal - this is a common phishing technique called typosquatting.'

        },

        {

        'id':4 ,

        'question':'What is the best defense against phishing?',

        'options':[

        'Using the same password everywhere',

        'Clicking links to verify legitimacy',

        'Two-factor authentication(2FA)',

        'Replying to suspicious emails'

        ],

        'correct':2 ,

        'explanation':'2FA adds an extra layer of security even if credentials are compromised.'

        },

        {

        'id':5 ,

        'question':'An email claims your account will be closed unless you verify immediately. What should you do?',

        'options':[

        'Click the link and verify quickly',

        'Reply with your account details',

        'Go directly to the website(not via email link)',

        'Forward to all contacts as warning'

        ],

        'correct':2 ,

        'explanation':'Always navigate to websites directly rather than through email links when dealing with account issues.'

        },

        {

        'id':6 ,

        'question':'Which is a red flag in an email address?',

        'options':[

        'support@company.com',

        'noreply@company.com',

        'support@company-verify.net',

        'info@company.com'

        ],

        'correct':2 ,

        'explanation':'Legitimate companies use their official domain. Extra words like "verify" in the domain are suspicious.'

        },

        {

        'id':7 ,

        'question':'What is "spear phishing"?',

        'options':[

        'Phishing using fish-related themes',

        'Targeted phishing against specific individuals',

        'Phishing via phone calls only',

        'Automated mass phishing campaigns'

        ],

        'correct':1 ,

        'explanation':'Spear phishing is highly targeted, using personal information to appear more legitimate.'

        },

        {

        'id':8 ,

        'question':'An attachment named "Invoice.pdf.exe" is likely:',

        'options':[

        'A legitimate PDF invoice',

        'A compressed invoice file',

        'Malware disguised as a PDF',

        'A secure encrypted document'

        ],

        'correct':2 ,

        'explanation':'The.exe extension reveals it\'s an executable file, not a PDF. This is a common malware technique.'

        },

        {

        'id':9 ,

        'question':'What should you do if you clicked a phishing link?',

        'options':[

        'Ignore it and hope for the best',

        'Change passwords and report to IT',

        'Delete the email and forget about it',

        'Reply to apologize'

        ],

        'correct':1 ,

        'explanation':'Quick action is crucial: change passwords immediately and report the incident.'

        },

        {

        'id':10 ,

        'question':'Which is the most secure password?',

        'options':[

        'Password123',

        'MyDogName2024',

        'Tr0ub4dor&3',

        'correct-horse-battery-staple'

        ],

        'correct':3 ,

        'explanation':'Long passphrases with random words are more secure and easier to remember than complex short passwords.'

        }

        ]



    def get_random_quiz(self, count :int =5 )->List[Dict ]:

        """Get random quiz questions"""

        return random.sample(self.quiz_bank, min(count, len(self.quiz_bank )))



    def check_answer(self, question_id :int, selected_option :int )->Dict :

        """Check if answer is correct and award XP"""

        #find question

        question =next((q for q in self.quiz_bank if q['id']==question_id ),None )



        if not question :

            return {'error':'Question not found'}



        is_correct =selected_option ==question['correct']



        #award XP if correct

        xp_earned =0 

        level_up =False 

        if is_correct :

            from config import XP_PER_QUIZ 

            xp_earned =XP_PER_QUIZ 

            level_up =self.db.add_xp(xp_earned )

            self.db.increment_stat('quizzes_completed')

            self.xp_updated.emit()



        return {

        'correct':is_correct ,

        'correct_answer':question['options'][question['correct']],

        'explanation':question['explanation'],

        'xp_earned':xp_earned ,

        'level_up':level_up 

        }



    def get_user_stats(self )->Dict :

        """Get user gamification statistics."""

        progress =self.db.get_user_progress()



        #calc progress to next level

        from config import LEVELS 

        current_level =progress['level']

        current_xp =progress['total_xp']



        if current_level <len(LEVELS ):

            next_level_xp =LEVELS[current_level ]

            #guard: level 0 has no previous threshold(min is 0 XP)

            prev_level_xp =LEVELS[current_level -1 ]if current_level >0 else 0 

            xp_in_band =next_level_xp -prev_level_xp 

            if xp_in_band >0 :

                progress_pct =((current_xp -prev_level_xp )/xp_in_band )*100 

            else :

                progress_pct =0 

        else :

            next_level_xp =current_xp 

            progress_pct =100 



        return {

        'level':current_level ,

        'total_xp':current_xp ,

        'next_level_xp':next_level_xp ,

        'progress_percentage':min(100, max(0, progress_pct )),

        'quizzes_completed':progress['quizzes_completed'],

        'scans_performed':progress['scans_performed']

        }



    def award_scan_xp(self ):

        """Award XP for performing a scan"""

        from config import XP_PER_SCAN 

        level_up =self.db.add_xp(XP_PER_SCAN )

        self.db.increment_stat('scans_performed')

        self.xp_updated.emit()

        return level_up 

