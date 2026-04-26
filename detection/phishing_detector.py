"""

ML-based Phishing Detection Engine.



Leverages a Random Forest Classifier to analyze URL lexicons and structural 

properties. Features are extracted statically to prevent active engagement 

with potentially malicious targets.

"""

import re 

from urllib.parse import urlparse 

from typing import Tuple, Dict, Any 

import numpy as np 

import joblib 

from sklearn.ensemble import RandomForestClassifier 

import config 

from security import SecurityValidator 





class PhishingDetector :

    """

    Heuristic and ML-driven URL classifier.

    

    Attributes:

        model(RandomForestClassifier): The underlying predictive model.

        validator(SecurityValidator): Utility for input sanitization.

    """



    def __init__(self ):

        """setup the detector and load/bootstrap the model artifact."""

        self.model =None 

        self.validator =SecurityValidator()

        self._load_or_train_model()



    def _load_or_train_model(self ):

        """

        Model Lifecycle Management.

        

        Attempts to load a pre-trained model from disk. If the artifact 

        is missing or corrupted, a new model is trained on synthetic data 

        to ensure operational readiness.

        """

        if config.PHISHING_MODEL_PATH.exists():

            try :

                self.model =joblib.load(config.PHISHING_MODEL_PATH )

            except Exception :

            #log warning: Model corruption detected, retraining

                self._train_model()

        else :

            self._train_model()



    def _train_model(self ):

        """

        Bootstrap a baseline model using synthetic heuristics.

        

        Note: In a production environment, this would be replaced by 

        an offline training pipeline using labeled datasets(e.g., PhishTank).

        """

        #make synthetic feature vectors for cold-start

        X_train, y_train =self._generate_training_data()



        #random Forest selected for interpretability and robustness involving tabular data

        self.model =RandomForestClassifier(

        n_estimators =50, 

        max_depth =10, 

        random_state =42 

        )

        self.model.fit(X_train, y_train )



        #persist model artifact

        joblib.dump(self.model, config.PHISHING_MODEL_PATH )



    def _generate_training_data(self )->Tuple[np.ndarray, np.ndarray ]:

        """

        Synthesize training samples based on feature distributions.

        

        Returns:

            Tuple: (Feature Matrix X, Label Vector y)

        """

        #safe URL Profile: Short, HTTPS, clean domain

        safe_features =np.random.rand(100, 8 )*0.3 



        #suspicious URL Profile: Longer, some special chars

        suspicious_features =np.random.rand(100, 8 )*0.5 +0.3 



        #malicious URL Profile: IP acts, deep paths, high keyword density

        malicious_features =np.random.rand(100, 8 )*0.4 +0.6 



        X =np.vstack([safe_features, suspicious_features, malicious_features ])

        y =np.array([0 ]*100 +[1 ]*100 +[2 ]*100 )#0 = Safe, 1 = Suspicious, 2 = Malicious



        return X, y 



    def extract_features(self, url :str )->np.ndarray :

        """

        Transform raw URL into a numerical feature vector.

        

        Feature Engineering Strategy:

        1. Lexical analysis(Length, special chars)

        2. Hostname analysis(IP usage, subdomain depth)

        3. Semantic analysis(Suspicious keyword density)

        

        Returns:

            np.ndarray: 1x8 Feature vector ready for inference.

        """

        parsed =urlparse(url )



        features =[

        self._url_length_score(url ),

        self._special_char_score(url ),

        self._has_ip_address(parsed.netloc ),

        self._suspicious_keywords_score(url ),

        self._subdomain_count(parsed.netloc ),

        self._has_https(parsed.scheme ),

        self._path_depth(parsed.path ),

        self._query_params_score(parsed.query )

        ]



        return np.array(features ).reshape(1 ,-1 )



    def _url_length_score(self, url :str )->float :

        """Heuristic: Excessively long URLs often obfuscate malicious payloads."""

        length =len(url )

        if length <50 :

            return 0.1 

        elif length <75 :

            return 0.3 

        elif length <100 :

            return 0.6 

        else :

            return 0.9 



    def _special_char_score(self, url :str )->float :

        """Heuristic: High density of special chars indicates obfuscation."""

        special_chars =len(re.findall(r'[@\-_\.]',url ))

        return min(special_chars /10, 1.0 )



    def _has_ip_address(self, netloc :str )->float :

        """Heuristic: Direct IP usage typically bypasses DNS reputation filters."""

        ip_pattern =r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

        return 1.0 if re.match(ip_pattern, netloc )else 0.0 



    def _suspicious_keywords_score(self, url :str )->float :

        """Heuristic: Social engineering terminology check."""

        url_lower =url.lower()

        count =sum(1 for keyword in self.validator.SUSPICIOUS_KEYWORDS 

        if keyword in url_lower )

        return min(count /3, 1.0 )



    def _subdomain_count(self, netloc :str )->float :

        """Heuristic: Multiple subdomains often mimic legitimate brands."""

        parts =netloc.split('.')

        subdomain_count =max(0, len(parts )-2 )

        return min(subdomain_count /3, 1.0 )



    def _has_https(self, scheme :str )->float :

        """Heuristic: Lack of SSL/TLS is a strong risk indicator."""

        return 0.0 if scheme =='https'else 0.7 



    def _path_depth(self, path :str )->float :

        """Heuristic: Deep directory structures may hide content."""

        depth =len([p for p in path.split('/')if p ])

        return min(depth /5, 1.0 )



    def _query_params_score(self, query :str )->float :

        """Heuristic: Complex query strings may indicate tracking or payloads."""

        if not query :

            return 0.0 

        param_count =len(query.split('&'))

        return min(param_count /5, 1.0 )



    def analyze_url(self, url :str )->Dict[str, Any ]:

        """

        Orchestrate the URL analysis pipeline.

        

        Flow:

        1. Input Sanitization & Validation

        2. Policy Checks(SSRF, Blocklists)

        3. Feature Extraction

        4. Model Inference

        5. Report Generation

        

        Returns:

            Dict: Comprehensive analysis report including risk scores and rationale.

        """

        #1. Validation Logic

        try :

            url =self.validator.sanitize_url(url )

            is_valid, msg =self.validator.is_valid_url(url )



            if not is_valid :

                return {

                'classification':'error',

                'risk_score':0 ,

                'color':config.COLOR_DANGER ,

                'error':msg 

                }



                #2. Policy Enforcement(SSRF Mitigation)

            if config.BLOCK_PRIVATE_IPS and self.validator.is_private_ip(url ):

                return {

                'classification':'blocked',

                'risk_score':1.0 ,

                'color':config.COLOR_DANGER ,

                'explanation':'Access denied: Target resolves to a private network address(SSRF Protection).'

                }



                #3 & 4. Feature Extraction and Inference with Whitelist Override

            trusted_domains =["google.com","microsoft.com","apple.com","github.com"]

            domain =urlparse(url ).netloc.lower()

            if domain.startswith("www."):

                domain =domain[4 :]



            features =self.extract_features(url )

            if domain in trusted_domains :

                risk_score =0.05 

            else :

                probabilities =self.model.predict_proba(features )[0 ]

                risk_score =float(probabilities[2 ])#index 2 = Malicious class probability



                #5. Classification Logic - Threshold Redefinition

            if risk_score <=0.40 :

                classification ='safe'

                color =config.COLOR_SAFE 

            elif risk_score <=0.85 :

                classification ='suspicious'

                color =config.COLOR_WARNING 

            else :

                classification ='malicious'

                color =config.COLOR_DANGER 



                #6. Explanation Generation

            explanation =self._generate_explanation(url, features[0 ],classification )



            return {

            'url':url ,

            'risk_score':risk_score ,

            'classification':classification ,

            'color':color ,

            'explanation':explanation ,

            'features':{

            'url_length':int(len(url )),

            'has_https':urlparse(url ).scheme =='https',

            'suspicious_keywords':self._count_suspicious_keywords(url )

            }

            }



        except Exception as e :

            return {

            'classification':'error',

            'risk_score':0 ,

            'color':config.COLOR_DANGER ,

            'error':f'Analysis Engine Failure: {str(e)}'

            }



    def _count_suspicious_keywords(self, url :str )->int :

        """Helper: Quantify social engineering keywords."""

        url_lower =url.lower()

        return sum(1 for keyword in self.validator.SUSPICIOUS_KEYWORDS 

        if keyword in url_lower )



    def _generate_explanation(self, url :str, features :np.ndarray, classification :str )->str :

        """Synthesize human-readable report based on active features."""

        explanations =[]



        if classification =='safe':

            explanations.append("✓ Domain reputation and structure appear legitimate.")

            if features[5 ]==0.0 :#feature index 5: HTTPS

                explanations.append("✓ Secure transport layer(HTTPS) detected.")

            if features[0 ]<0.3 :#feature index 0: Length

                explanations.append("✓ URL length falls within normal parameters.")



        elif classification =='suspicious':

            explanations.append("⚠ Anomalous characteristics detected; proceed with caution.")

            if features[5 ]>0.0 :

                explanations.append("⚠ Insecure connection(HTTP) exposes data to interception.")

            if features[3 ]>0.3 :

                explanations.append("⚠ Heuristic match for social engineering keywords.")



        else :#maliciously classified

            explanations.append("✗ High-confidence threats identified.")

            if features[2 ]>0.5 :

                explanations.append("✗ Direct IP usage bypasses DNS controls.")

            if features[3 ]>0.5 :

                explanations.append("✗ Significant density of phishing terminology.")

            if features[0 ]>0.7 :

                explanations.append("✗ Excessive URL length indicates potential payload obfuscation.")



        return "\n".join(explanations )

