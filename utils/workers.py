import sys 
import traceback 
from PyQt6.QtCore import QObject, QRunnable, pyqtSignal, pyqtSlot 

class WorkerSignals(QObject ):
    """
    Defines the signals available from a running worker thread.
    Supported signals are:
    - result: `object` data returned from processing
    - error: `tuple` (exctype, value, traceback.format_exc())
    - finished: No data, emitted when the thread finishes execution
    """
    result =pyqtSignal(object )
    error =pyqtSignal(tuple )
    finished =pyqtSignal()

class Worker(QRunnable ):
    """
    Generic Worker thread utilizing QRunnable.
    Takes a target asynchronous method and runs it without blocking the main GUI loop.
    """
    def __init__(self, fn ,*args ,**kwargs ):
        super(Worker, self ).__init__()
        self.fn =fn 
        self.args =args 
        self.kwargs =kwargs 
        self.signals =WorkerSignals()

    @pyqtSlot()
    def run(self ):
        """
        Invoked by the QThreadPool. Runs the targeted function and emits associated signals.
        """
        try :
            result =self.fn(*self.args ,**self.kwargs )
        except Exception :
            traceback.print_exc()
            exctype, value =sys.exc_info()[:2 ]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else :
            self.signals.result.emit(result )
        finally :
            self.signals.finished.emit()

from PyQt6.QtCore import QThread 
class AIQueryThread(QThread ):
    def __init__(self, fn ,*args ,**kwargs ):
        super().__init__()
        self.fn =fn 
        self.args =args 
        self.kwargs =kwargs 
        self.signals =WorkerSignals()

    def run(self ):
        try :
            result =self.fn(*self.args ,**self.kwargs )
        except Exception :
            traceback.print_exc()
            exctype, value =sys.exc_info()[:2 ]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else :
            self.signals.result.emit(result )
        finally :
            self.signals.finished.emit()
