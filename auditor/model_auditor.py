"""

ML Model Reliability & Governance Auditor.



Performs continuous monitoring of deployed machine learning artifacts.

Key assessments:

- Drift Detection: Uses Kolmogorov-Smirnov(KS) tests to identify statistical divergence.

- Adversarial Robustness: Evaluates model stability under perturbation.

"""

from typing import Dict, List, Any 

import numpy as np 

from scipy import stats 

import joblib 

import config 





class ModelAuditor :

    """

    Automated auditing framework for ModelOps.

    

    Attributes:

        phishing_model: Loaded instance of PhishingDetector model.

        anomaly_model: Loaded instance of AnomalyDetector model.

    """



    def __init__(self ):

        """setup auditor and hydrate model references."""

        self.phishing_model =None 

        self.anomaly_model =None 

        self._load_models()



    def _load_models(self ):

        """

        Dynamically load model artifacts for inspection.

        

        Handles absence of models gracefully to allow partial auditing.

        """

        try :

            if config.PHISHING_MODEL_PATH.exists():

                self.phishing_model =joblib.load(config.PHISHING_MODEL_PATH )

        except Exception :

        #model may not be trained yet

            pass 



        try :

            if config.ANOMALY_MODEL_PATH.exists():

                self.anomaly_model =joblib.load(config.ANOMALY_MODEL_PATH )

        except Exception :

            pass 



    def audit_phishing_model(self )->Dict[str, Any ]:

        """

        runs comprehensive audit on the Phishing Detector.

        

        Evaluates:

        1. Metadata verification

        2. Feature drift analysis

        3. Adversarial vulnerability assessment

        4. Overall health scoring

        

        Returns:

            Dict: Detailed audit report.

        """

        if not self.phishing_model :

            return {'error':'Phishing model artifact not found'}



        results ={

        'model_type':type(self.phishing_model ).__name__ ,

        'metadata':self._get_model_metadata('phishing'),

        'drift_analysis':self._detect_drift('phishing'),

        'robustness_test':self._test_adversarial_robustness('phishing'),

        'health_score':0 

        }



        #calc algorithmic health score

        health_score =100 

        if results['drift_analysis'].get('drift_detected',False ):

            health_score -=30 

        if results['robustness_test'].get('vulnerability_score',0 )>0.5 :

            health_score -=20 



        results['health_score']=max(0, health_score )



        return results 



    def audit_anomaly_model(self )->Dict[str, Any ]:

        """

        runs comprehensive audit on the Anomaly Detector.

        

        Evaluates:

        1. Metadata verification

        2. Feature drift analysis

        

        Returns:

            Dict: Detailed audit report.

        """

        if not self.anomaly_model :

            return {'error':'Anomaly model artifact not found'}



        results ={

        'model_type':type(self.anomaly_model ).__name__ ,

        'metadata':self._get_model_metadata('anomaly'),

        'drift_analysis':self._detect_drift('anomaly'),

        'health_score':0 

        }



        #calc algorithmic health score

        health_score =100 

        if results['drift_analysis'].get('drift_detected',False ):

            health_score -=30 



        results['health_score']=max(0, health_score )



        return results 



    def _get_model_metadata(self, model_type :str )->Dict[str, Any ]:

        """Extract physical and hyperparameter metadata from model artifacts."""

        if model_type =='phishing':

            model =self.phishing_model 

            path =config.PHISHING_MODEL_PATH 

        else :

            model =self.anomaly_model 

            path =config.ANOMALY_MODEL_PATH 



        metadata ={

        'model_file':path.name ,

        'file_size_kb':path.stat().st_size /1024 if path.exists()else 0 ,

        }



        #introspect model-specific hyperparameters

        if hasattr(model ,'n_estimators'):

            metadata['n_estimators']=model.n_estimators 

        if hasattr(model ,'max_depth'):

            metadata['max_depth']=model.max_depth 



        return metadata 



    def _detect_drift(self, model_type :str )->Dict[str, Any ]:

        """

        Statistical Concept Drift Detection.

        

        Uses Kolmogorov-Smirnov(KS) test to compare the distributions of 

        baseline training data vs. current production data.

        

        Note: Currently uses simulated production data for demonstration.

        In production, this would sample from live feature stores.

        """

        #make reference data(training distribution)

        reference_data =np.random.rand(100, 8 )



        #make current data(simulated production data with potential shift)

        current_data =np.random.rand(100, 8 )+0.1 #simulated drift of 0.1



        #perform KS test for each feature dimension

        drift_detected =False 

        feature_drifts =[]



        for i in range(reference_data.shape[1 ]):

            statistic, p_value =stats.ks_2samp(reference_data[:,i ],current_data[:,i ])



            #hypothesis test: Null hypothesis = distributions are identical

            #p-value < 0.05 implies rejection of null hypothesis -> Drift detected

            is_drift =p_value <0.05 

            if is_drift :

                drift_detected =True 



            feature_drifts.append({

            'feature_index':i ,

            'ks_statistic':float(statistic ),

            'p_value':float(p_value ),

            'drift_detected':is_drift 

            })



        return {

        'drift_detected':drift_detected ,

        'test_method':'Kolmogorov-Smirnov',

        'feature_drifts':feature_drifts ,

        'recommendation':'Retrain model on new data'if drift_detected else 'Model is stable'

        }



    def _test_adversarial_robustness(self, model_type :str )->Dict[str, Any ]:

        """

        Adversarial Attack Simulation.

        

        Tests model resilience by injecting Gaussian noise(perturbations) 

        into input features and measuring prediction stability(Label Flip Rate).

        """

        if model_type !='phishing':

            return {}



            #make baseline benign samples

        normal_samples =np.random.rand(50, 8 )*0.3 #feature space characteristic of 'Safe' URLs



        #defined perturbation magnitudes(epsilon)

        perturbation_sizes =[0.01, 0.05, 0.1, 0.2 ]

        results =[]



        for epsilon in perturbation_sizes :

        #inject noise

            perturbed =normal_samples +np.random.randn(50, 8 )*epsilon 

            perturbed =np.clip(perturbed, 0 ,1 )#constrain to valid feature range[0, 1]



            #comparative Inference

            original_preds =self.phishing_model.predict(normal_samples )

            perturbed_preds =self.phishing_model.predict(perturbed )



            #calc Label Flip Rate(Stability Metric)

            flip_rate =np.mean(original_preds !=perturbed_preds )



            results.append({

            'perturbation':epsilon ,

            'flip_rate':float(flip_rate )

            })



            #aggregate vulnerability score

        avg_flip_rate =np.mean([r['flip_rate']for r in results ])



        return {

        'test_results':results ,

        'vulnerability_score':float(avg_flip_rate ),

        'assessment':'Critical Vulnerability'if avg_flip_rate >0.3 else 'Robust'

        }



    def get_full_audit_report(self )->Dict[str, Any ]:

        """Compile executive summary of all model states."""

        return {

        'phishing_model':self.audit_phishing_model(),

        'anomaly_model':self.audit_anomaly_model(),

        'timestamp':np.datetime64('now').astype(str )

        }

