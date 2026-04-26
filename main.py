"""

Cybersecurity Companion.



A privacy-focused desktop security assistant leveraging local AI models

for phishing detection, anomaly analysis, and educational guidance.



Architecture:

    - Frontend: PyQt6(MVC Pattern)

    - Detection: Scikit-learn(Random Forest, Isolation Forest)

    - AI Assistant: RAG pipeline with Sentence Transformers

    - Storage: SQLite + Local File System

"""

import sys 

from PyQt6.QtCore import Qt 

from PyQt6.QtWidgets import QApplication 

from PyQt6.QtGui import QIcon 



#cRITICAL EXECUTABLE FIX: WebEngine must setup OpenGL contexts

#*before* the parent QCoreApplication instance evaluates main memory

import PyQt6.QtWebEngineCore 

import PyQt6.QtWebEngineWidgets 



from ui import MainWindow 

import config 





def main():

    """

    setup and launch the application.

    

    Sets up the Qt Application context, applies global styling,

    and instantiates the main window controller.

    """

    #target Environments: Low-Spec Hardware / Integrated GPU

    #disable hardware acceleration to prevent driver crashes

    import os 



    #force software rendering and disable scaling bloat via OS environment

    os.environ["QT_ENABLE_HIGHDPI_SCALING"]="0"

    os.environ["QT_QUICK_BACKEND"]="software"

    os.environ["QT_DEVICE_PIXEL_RATIO"]="1"



    sys.argv.extend([

    "--disable-gpu",

    "--disable-software-rasterizer",

    "--disable-gpu-compositing",

    "--disable-gpu-rasterization",

    "--disable-accelerated-2d-canvas",

    "--disable-webgl",

    "--disable-backdrop-filter",#disable Backdrop Filters

    "--wm-window-animations-disabled",#remove 3D Transforms / Complex Animations

    "--disable-dev-shm-usage"#crucial for low-RAM enterprise machines

    ])



    QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseSoftwareOpenGL )



    #setup Core Application Context

    app =QApplication(sys.argv )

    app.setApplicationName(config.APP_NAME )

    app.setApplicationVersion(config.APP_VERSION )

    app.setOrganizationName(config.APP_AUTHOR )



    #apply 'Fusion' style for consistent cross-platform rendering

    app.setStyle('Fusion')



    #setup Main Controller

    window =MainWindow()

    window.show()



    #runs Event Loop

    sys.exit(app.exec())





if __name__ =='__main__':

    main()

