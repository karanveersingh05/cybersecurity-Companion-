"""

db Abstraction Layer(DAL).



Manages persistence for security events, analysis results, and user

metrics using an embedded SQLite engine. Enforces data integrity

and provides transactional scoping for critical updates.

"""

import sqlite3 

import logging 

import os 

from datetime import datetime 

from typing import List, Dict, Optional 

import config 



logger =logging.getLogger(__name__ )





class DatabaseManager :

    """

    Core data access object(DAO) for application state persistence.

    

    Handles schema initialization, migration checks, and provides

    high-level methods for querying analytics and audit logs.

    """



    def __init__(self, db_path :str =None ):

        """

        setup db connection context.

        

        Args:

            db_path(str, optional): Override default db path for testing.

        """

        self.db_path =db_path or str(config.DB_PATH )

        self.init_database()



    def init_database(self ):

        """

        Bootstrap db schema.

        

        Creates necessary tables(alerts, scans, user_progress) if they

        do not exist. Implicitly handles idempotent initialization.

        """

        #ensure the directory exists before connecting

        os.makedirs(os.path.dirname(self.db_path ),exist_ok =True )



        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()



            #security Events / Alerts Audit Log

            cursor.execute("""

                CREATE TABLE IF NOT EXISTS alerts(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    timestamp TEXT NOT NULL,

                    alert_type TEXT NOT NULL,

                    severity TEXT NOT NULL,

                    description TEXT NOT NULL,

                    details TEXT

                )

            """)



            #analysis History / Scan Repository

            cursor.execute("""

                CREATE TABLE IF NOT EXISTS scans(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    timestamp TEXT NOT NULL,

                    scan_type TEXT NOT NULL,

                    target TEXT NOT NULL,

                    result TEXT NOT NULL,

                    score REAL

                )

            """)



            #browser History Risk Tracker

            cursor.execute("""

                CREATE TABLE IF NOT EXISTS browser_history(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    timestamp TEXT NOT NULL,

                    url TEXT NOT NULL,

                    domain TEXT NOT NULL,

                    risk_score INTEGER,

                    risk_level TEXT,

                    threat_type TEXT

                )

            """)



            #user Engagement & Training Metrics(Singleton Record)

            cursor.execute("""

                CREATE TABLE IF NOT EXISTS user_progress(

                    id INTEGER PRIMARY KEY CHECK(id = 1),

                    total_xp INTEGER DEFAULT 0,

                    level INTEGER DEFAULT 1,

                    quizzes_completed INTEGER DEFAULT 0,

                    scans_performed INTEGER DEFAULT 0

                )

            """)



            #seed initial user state if db is fresh

            cursor.execute("""

                INSERT OR IGNORE INTO user_progress(id, total_xp, level)

                VALUES(1, 0, 1)

            """)



            conn.commit()

            logger.debug("Database schema initialized successfully.")



    def add_alert(self, alert_type :str, severity :str, description :str, details :str =""):

        """

        Persist a security alert event.

        

        Args:

            alert_type: Category of the threat(e.g., 'phishing', 'anomaly').

            severity: Impact classification('low', 'medium', 'high', 'critical').

            description: High-level summary of the event.

            details: Technical specifics or raw data payload.

        """

        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()

            cursor.execute("""

                INSERT INTO alerts(timestamp, alert_type, severity, description, details)

                VALUES(?, ?, ?, ?, ?)

            """,(datetime.now().isoformat(),alert_type, severity, description, details ))

            conn.commit()



    def get_recent_alerts(self, limit :int =10 )->List[Dict ]:

        """

        get latest security alerts for dashboard visualization.

        

        Args:

            limit: Maximum number of records to return.

            

        Returns:

            List of alert records as dictionaries.

        """

        with sqlite3.connect(self.db_path )as conn :

            conn.row_factory =sqlite3.Row 

            cursor =conn.cursor()

            cursor.execute("""

                SELECT * FROM alerts 

                ORDER BY timestamp DESC 

                LIMIT ?

            """,(limit ,))

            return[dict(row )for row in cursor.fetchall()]



    def get_active_alerts_count(self )->int :

        """

        Fetch the absolute total of active threat alerts efficiently.

        """

        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM alerts")

            return cursor.fetchone()[0 ]



    def add_scan(self, scan_type :str, target :str, result :str, score :float =None ):

        """

        Record an analysis operation(scan) result.

        

        Used for audit trails and calculating system security score.

        """

        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()

            cursor.execute("""

                INSERT INTO scans(timestamp, scan_type, target, result, score)

                VALUES(?, ?, ?, ?, ?)

            """,(datetime.now().isoformat(),scan_type, target, result, score ))

            conn.commit()



    def add_browser_history(self, url :str, domain :str, risk_score :int, risk_level :str, threat_type :str =""):

        """Log a visited URL and its corresponding threat classification to history."""

        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()

            cursor.execute("""

                INSERT INTO browser_history(timestamp, url, domain, risk_score, risk_level, threat_type)

                VALUES(?, ?, ?, ?, ?, ?)

            """,(datetime.now().isoformat(),url, domain, risk_score, risk_level, threat_type ))

            conn.commit()



    def get_browser_history(self, limit :int =50 )->List[Dict ]:

        """Fetch latest browser navigation history logs."""

        with sqlite3.connect(self.db_path )as conn :

            conn.row_factory =sqlite3.Row 

            cursor =conn.cursor()

            cursor.execute("SELECT * FROM browser_history ORDER BY timestamp DESC LIMIT ?",(limit ,))

            return[dict(row )for row in cursor.fetchall()]





    def get_user_progress(self )->Dict :

        """Fetch current gamification metrics(XP, Level).

        

        Null-safe: if the singleton row is missing(e.g. external DB deletion),

        re-seeds and returns a default record instead of crashing.

        """

        with sqlite3.connect(self.db_path )as conn :

            conn.row_factory =sqlite3.Row 

            cursor =conn.cursor()

            cursor.execute("SELECT * FROM user_progress WHERE id = 1")

            row =cursor.fetchone()

            if row is None :

            #re-seed the singleton row and return defaults

                logger.warning("user_progress singleton row missing — re-seeding.")

                cursor.execute(

                "INSERT OR IGNORE INTO user_progress(id, total_xp, level) VALUES(1, 0, 1)"

                )

                conn.commit()

                return {'id':1 ,'total_xp':0 ,'level':1 ,

                'quizzes_completed':0 ,'scans_performed':0 }

            return dict(row )



    def add_xp(self, xp :int )->bool :

        """

        Increment user XP and handle level progression logic.

        

        Returns:

            bool: True if the user leveled up, False otherwise.

        """

        progress =self.get_user_progress()

        new_xp =progress['total_xp']+xp 

        new_level =self._calculate_level(new_xp )



        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()

            cursor.execute("""

                UPDATE user_progress 

                SET total_xp = ?, level = ?

                WHERE id = 1

            """,(new_xp, new_level ))

            conn.commit()



        return new_level >progress['level']



    def increment_stat(self, stat_name :str ):

        """

        Atomically increment a specific user statistic.

        

        Args:

            stat_name: Column name to increment(must be sanitized/safe).

        """

        allowed_stats =['quizzes_completed','scans_performed']

        if stat_name not in allowed_stats :

            raise ValueError(f"Invalid stat_name: {stat_name}")



        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()

            cursor.execute(f"""

                UPDATE user_progress 

                SET {stat_name} = {stat_name} + 1

                WHERE id = 1

            """)

            conn.commit()



    def _calculate_level(self, xp :int )->int :

        """Derive user level based on cumulative XP thresholds."""

        for level, threshold in enumerate(config.LEVELS, 1 ):

            if xp <threshold :

                return level -1 

        return len(config.LEVELS )



    def get_security_score(self )->int :

        """

        Compute holistic system security score(0-100).

        

        Algorithm considers:

        1. Recency of scans(Activity Bonus)

        2. Unresolved critical alerts(Risk Penalty)

        

        Returns:

            int: Calculated security score.

        """

        with sqlite3.connect(self.db_path )as conn :

            cursor =conn.cursor()



            #metric: Scan Activity(Last 7 Days)

            cursor.execute("""

                SELECT COUNT(*) FROM scans 

                WHERE timestamp > datetime('now', '-7 days')

            """)

            recent_scans =cursor.fetchone()[0 ]



            #metric: Critical Threat Volume(Last 7 Days)

            cursor.execute("""

                SELECT COUNT(*) FROM alerts 

                WHERE severity = 'critical' 

                AND timestamp > datetime('now', '-7 days')

            """)

            critical_alerts =cursor.fetchone()[0 ]



            #scoring Logic

            base_score =70.0 

            scan_bonus =min(recent_scans *2.0, 20.0 )

            alert_penalty =min(critical_alerts *10.0, 40.0 )



            score =max(0, min(100, int(base_score +scan_bonus -alert_penalty )))

            return score 

