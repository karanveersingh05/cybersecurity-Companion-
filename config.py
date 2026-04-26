"""

Application config & Constants.



Centralizes runtime settings, file paths, model parameters, and UI themes.

Handles path resolution for both development and frozen(PyInstaller) environments.

"""

import os 

import sys 

from pathlib import Path 



#-- Application Metadata --

APP_NAME ="Cybersecurity Companion"

APP_VERSION ="1.0.0"

APP_AUTHOR ="B.Tech CSE Final Year Project"



#-- Environment Resolution --

#resolves paths dynamically based on runtime context(Source vs Frozen Executable)

if getattr(sys ,'frozen',False ):

#pyInstaller runtime: Resources unpacked to _MEIPASS, Data persists in executable dir

#use getattr to satisfy linter for _MEIPASS which is injected at runtime

    _meipass =getattr(sys ,'_MEIPASS',os.path.dirname(os.path.abspath(__file__ )))

    INTERNAL_DIR =Path(_meipass )

    EXTERNAL_DIR =Path(sys.executable ).parent 

else :

#development runtime: All paths relative to source root

    INTERNAL_DIR =Path(__file__ ).parent 

    EXTERNAL_DIR =Path(__file__ ).parent 





    #-- Internal Assets --

BASE_DIR =INTERNAL_DIR 

ASSETS_DIR =INTERNAL_DIR /"assets"

ICON_PATH =ASSETS_DIR /"icon.png"

LOGO_PATH =ASSETS_DIR /"logo.png"



#-- Persistent Data Storage --

#critical data and trained models reside in external writable storage

DATA_DIR =EXTERNAL_DIR /"data"

MODELS_DIR =EXTERNAL_DIR /"models"

DB_PATH =DATA_DIR /"cybersec.db"



#ensure data directories exist

for directory in[DATA_DIR, MODELS_DIR ]:

    directory.mkdir(exist_ok =True, parents =True )



    #-- ML Model Artifacts --

PHISHING_MODEL_PATH =MODELS_DIR /"phishing_detector.pkl"

ANOMALY_MODEL_PATH =MODELS_DIR /"anomaly_detector.pkl"

VECTORIZER_PATH =MODELS_DIR /"log_vectorizer.pkl"

EMBEDDINGS_MODEL ="all-MiniLM-L6-v2"



#-- RAG & Knowledge Base --

FAISS_INDEX_PATH =MODELS_DIR /"knowledge_base.faiss"

KNOWLEDGE_DOCS_PATH =DATA_DIR /"knowledge_base.json"

MAX_RAG_RESULTS =3 

LLM_MAX_TOKENS =256 



#-- Detection Parameters --

PHISHING_THRESHOLD_SAFE =0.3 

PHISHING_THRESHOLD_SUSPICIOUS =0.7 

ANOMALY_CONTAMINATION =0.1 



#-- UI Theme config --

COLOR_SAFE ="#2ecc71"

COLOR_WARNING ="#f39c12"

COLOR_DANGER ="#e74c3c"

COLOR_PRIMARY ="#3498db"

COLOR_DARK ="#2c3e50"

COLOR_LIGHT ="#ecf0f1"

COLOR_SURFACE ="#ffffff"

COLOR_BACKGROUND ="#f5f6fa"

COLOR_BORDER ="#dcdde1"

COLOR_TEXT ="#2c3e50"

COLOR_SECONDARY ="#7f8c8d"

FONT_FAMILY ="Segoe UI"



#-- System Constraints --

MAX_LOG_LINES =10000 

URL_CHECK_TIMEOUT =0.2 

MAX_MEMORY_MB =300 



#-- Gamification Metrics --

XP_PER_QUIZ =10 

XP_PER_SCAN =5 

LEVELS =[0, 100, 250, 500, 1000, 2000 ]



#-- Security Policies --

ENABLE_MODEL_VERIFICATION =True 

SANITIZE_INPUTS =True 

BLOCK_PRIVATE_IPS =True 



#-- db Schema --

DB_VERSION =1 

