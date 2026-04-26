"""

Anomaly Detection Logic.



adds an unsupervised learning pipeline using Isolation Forest to identify 

outliers in system logs. Text logs are vectorized using TF-IDF to capture 

semantic context before anomaly scoring.

"""

import re 

from typing import List, Dict, Tuple, Any 

import numpy as np 

import joblib 

from sklearn.ensemble import IsolationForest 

from sklearn.feature_extraction.text import TfidfVectorizer 

import config 

from security import SecurityValidator 





class AnomalyDetector :

    """

    Log Analysis Engine using density-based outlier detection.

    

    Attributes:

        model(IsolationForest): Unsupervised anomaly detection model.

        vectorizer(TfidfVectorizer): Text feature extraction model.

    """



    def __init__(self ):

        """setup models and load persistent artifacts."""

        self.model =None 

        self.vectorizer =None 

        self.validator =SecurityValidator()

        self._load_or_train_model()



    def _load_or_train_model(self ):

        """

        Model Lifecycle Management.

        

        Loads pre-calculated vectorizer vocabulary and forest structure.

        Falls back to comprehensive retraining if artifacts are absent or corrupted.

        """

        if config.ANOMALY_MODEL_PATH.exists()and config.VECTORIZER_PATH.exists():

            try :

                self.model =joblib.load(config.ANOMALY_MODEL_PATH )

                self.vectorizer =joblib.load(config.VECTORIZER_PATH )

                #check artifacts loaded correctly with vocabulary integrity

                if not hasattr(self.vectorizer ,'vocabulary_')or not self.vectorizer.vocabulary_ :

                    print("Warning: Loaded vectorizer has no vocabulary. Retraining.")

                    self._train_model()

            except(EOFError, ModuleNotFoundError )as e :

                print(f"Warning: Model artifact corrupted({type(e).__name__}). Retraining.")

                self._train_model()

            except Exception :

            #log error: Artifact mismatch or corruption

                self._train_model()

        else :

            self._train_model()



    def _train_model(self ):

        """

        Train the anomaly detection pipeline.

        

        build a TF-IDF vector space from a baseline of 'normal' system 

        behaviors and fits an Isolation Forest to define the normality boundary.

        """

        #make baseline normal traffic for unsupervised training

        normal_logs =self._generate_normal_logs(200 )



        #configure TF-IDF(1-2 ngrams to capture phrases like "login failed")

        self.vectorizer =TfidfVectorizer(max_features =100, ngram_range =(1, 2 ))

        X_train =self.vectorizer.fit_transform(normal_logs )



        #train Isolation Forest

        self.model =IsolationForest(

        contamination =config.ANOMALY_CONTAMINATION, 

        random_state =42, 

        n_estimators =50 

        )

        self.model.fit(X_train.toarray())



        #persist trained state

        joblib.dump(self.model, config.ANOMALY_MODEL_PATH )

        joblib.dump(self.vectorizer, config.VECTORIZER_PATH )



    def _generate_normal_logs(self, count :int )->List[str ]:

        """Synthesize baseline 'normal' operational logs for training context."""

        normal_patterns =[

        "INFO User login successful user = john",

        "INFO System startup completed",

        "DEBUG Database connection established",

        "INFO File access granted path=/home/user/docs",

        "INFO Session created session_id = abc123",

        "DEBUG Cache hit key = user_profile",

        "INFO Request processed status = 200",

        "DEBUG Memory usage normal 45%",

        ]



        logs =[]

        for _ in range(count ):

            logs.append(np.random.choice(normal_patterns ))



        return logs 



    def analyze_logs(self, log_content :str )->Dict[str, Any ]:

        """

        Process raw log streams to detect outliers and security incidents.

        

        Pipeline:

        1. Parsing & Sanitization

        2. TF-IDF Vectorization

        3. Isolation Forest Inference(Anomaly Scoring)

        4. Heuristic Pattern Matching for specific attack signatures

        

        Returns:

            Dict: Analysis report including anomaly count, severity, and details.

        """

        try :

        #1. Parsing and Normalization

            lines =log_content.strip().split('\n')



            #enforce resource limits

            if len(lines )>config.MAX_LOG_LINES :

                lines =lines[:config.MAX_LOG_LINES ]



                #sanitize input to prevent injection in downstream tools

            lines =[self.validator.sanitize_log_line(line )for line in lines if line.strip()]



            if not lines :

                return {

                'error':'Input contained no valid log lines',

                'anomaly_count':0 

                }



                #2. Feature Extraction

            X =self.vectorizer.transform(lines )



            #3. Model Inference

            #predict(): -1 for outliers, 1 for inliers

            predictions =self.model.predict(X.toarray())

            #score_samples(): raw anomaly scores(lower is more anomalous)

            anomaly_scores =self.model.score_samples(X.toarray())



            #filter and annotate anomalies

            anomalies =[]

            for i ,(pred, score, line )in enumerate(zip(predictions, anomaly_scores, lines )):

                if pred ==-1 :

                    anomalies.append({

                    'line_number':i +1 ,

                    'content':line[:200 ],#truncate for display

                    'score':float(score ),

                    'reason':self._analyze_anomaly_reason(line )

                    })



                    #4. Risk Assessment

            anomaly_rate =len(anomalies )/len(lines )



            if anomaly_rate <0.05 :

                severity ='low'

                color =config.COLOR_SAFE 

                message ="Operational Status: Normal"

            elif anomaly_rate <0.15 :

                severity ='medium'

                color =config.COLOR_WARNING 

                message ="Warning: Elevated anomalous activity detected"

            else :

                severity ='high'

                color =config.COLOR_DANGER 

                message ="CRITICAL: Significant security deviations detected"



            return {

            'total_lines':len(lines ),

            'anomaly_count':len(anomalies ),

            'anomaly_rate':anomaly_rate ,

            'severity':severity ,

            'color':color ,

            'message':message ,

            'anomalies':anomalies[:20 ],#return top 20 for UI performance

            'patterns_detected':self._detect_attack_patterns(lines )

            }



        except Exception as e :

            return {

            'error':f'Analysis Pipeline Failure: {str(e)}',

            'anomaly_count':0 

            }



    def _analyze_anomaly_reason(self, log_line :str )->str :

        """Heuristic: map raw log text to potential incident types."""

        log_lower =log_line.lower()



        #auth Failures

        if re.search(r'fail|denied|unauthorized|invalid',log_lower ):

            return "Potential Brute Force / Auth Failure"



            #privilege Escalation

        if re.search(r'sudo|admin|root|privilege',log_lower ):

            return "Privilege Escalation Attempt"



            #remote Code Execution(RCE) indicators

        if re.search(r'rm -rf|wget|curl|nc |netcat|/bin/sh',log_lower ):

            return "Suspicious Shell Command / RCE"



            #reconnaissance

        if re.search(r'port.*scan|nmap|masscan',log_lower ):

            return "Network Reconnaissance / Port Scan"



            #injection Attacks

        if re.search(r'union.*select|drop.*table|exec\(',log_lower ):

            return "SQL/Command Injection Signature"



        return "Statistical Anomaly(Unknown Pattern)"



    def _detect_attack_patterns(self, lines :List[str ])->Dict[str, int ]:

        """

        Scan for deterministic attack signatures across the log batch.

        

        Returns:

            Dict: Counts of detected attack vectors.

        """

        patterns ={

        'failed_logins':0 ,

        'privilege_escalation':0 ,

        'suspicious_commands':0 ,

        'sql_injection':0 

        }



        for line in lines :

            log_lower =line.lower()



            if re.search(r'fail.*login|authentication.*fail',log_lower ):

                patterns['failed_logins']+=1 



            if re.search(r'sudo|admin|root',log_lower ):

                patterns['privilege_escalation']+=1 



            if re.search(r'rm -rf|wget|curl|nc ',log_lower ):

                patterns['suspicious_commands']+=1 



            if re.search(r'union.*select|drop.*table',log_lower ):

                patterns['sql_injection']+=1 



        return patterns 

