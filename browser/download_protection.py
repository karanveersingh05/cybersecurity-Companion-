import os 
from PyQt6.QtWidgets import QMessageBox 
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest 
import logging 

logger =logging.getLogger(__name__ )

class DownloadProtector :
    """
    Evaluates WebEngine download requests to flag potentially malicious binaries.
    """

    DANGEROUS_EXTENSIONS =(
    '.exe','.bat','.scr','.vbs','.js',
    '.msi','.cmd','.ps1','.zip','.rar',
    '.iso','.dll','.jar','.hta'
    )

    @staticmethod 
    def evaluate_download(download :QWebEngineDownloadRequest, parent_widget, db_manager )->None :
        """
        Check the downloaded filename against dangerous extensions.
        If dangerous, prompt user with a QMessageBox.
        If accepted, proceed. Also logs to the db regardless.
        """
        try :
            url =download.url().toString()
            filename =download.suggestedFileName()
            _, ext =os.path.splitext(filename )
            ext =ext.lower()

            is_dangerous =ext in DownloadProtector.DANGEROUS_EXTENSIONS 

            #log to db
            if db_manager :
                db_manager.add_alert(
                alert_type ="download",
                severity ="HIGH"if is_dangerous else "LOW",
                description =f"File download requested: {filename}",
                details =f"URL: {url}"
                )

            if is_dangerous :
                logger.warning(f"Intercepted potentially dangerous download: {filename}")
                msg =QMessageBox(parent_widget )
                msg.setIcon(QMessageBox.Icon.Warning )
                msg.setWindowTitle("Dangerous File Type Detected")
                msg.setText(f"The file **{filename}** has an extension({ext}) that can execute code on your computer.")
                msg.setInformativeText("Only download and open this file if you completely trust this website. Proceed with download?")
                msg.setStandardButtons(QMessageBox.StandardButton.Yes |QMessageBox.StandardButton.No )
                msg.setDefaultButton(QMessageBox.StandardButton.No )

                res =msg.exec()
                if res ==QMessageBox.StandardButton.No :
                    download.cancel()
                    logger.info("Download cancelled by user.")
                    return 

                    #accept download path dialog natively(or silently accept to default)
            download.accept()
            logger.info("Download accepted.")

        except Exception as e :
            logger.error(f"Download evaluation failed: {e}")
            download.cancel()
