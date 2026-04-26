"""
UI Animation and Transition Utilities.

Provides reusable animations for various UI elements to ensure a responsive,
modern user experience while keeping the main thread non-blocking.
"""
from PyQt6.QtWidgets import(QWidget, QGraphicsOpacityEffect, QAbstractSlider, 
QPushButton )
from PyQt6.QtCore import(QPropertyAnimation, QRect, QPoint, QEasingCurve, 
QTimer, QParallelAnimationGroup, QObject, QEvent )
from PyQt6.QtGui import QColor 

def fade_in(widget :QWidget, duration :int =300 ):
    """
    ENTERPRISE-LITE OVERRIDE:
    Hardware acceleration is disabled. Replaced QPropertyAnimation/Opacity 
    gradients with immediate unblocking.show() to save GPU cycles.
    """
    if not widget.isVisible():
        widget.show()
    return None 

def slide_and_fade(widget :QWidget, start_pos :QPoint, end_pos :QPoint, duration :int =400 ):
    """
    ENTERPRISE-LITE OVERRIDE:
    Replaced complex slide-ins and property animations with immediate
    repositioning and.show() to eliminate GPU frame starvation scenarios.
    """
    widget.move(end_pos )
    if not widget.isVisible():
        widget.show()
    return None 

class GlobalHoverFilter(QObject ):
    def __init__(self, duration =200 ):
        super().__init__()
        self.duration =duration 

    def eventFilter(self, obj, event ):
        if isinstance(obj, QPushButton )and not obj.property("no_hover_anim"):
            if event.type()==QEvent.Type.Enter :
                self._animate(obj, True )
            elif event.type()==QEvent.Type.Leave :
                self._animate(obj, False )
        return False 

    def _animate(self, button, enter ):
    #eNTERPRISE-LITE OVERRIDE:
    #removed QGraphicsOpacityEffect handling. Using native CSS hover
    #states instead of explicit Python-side property animations
        pass 

_global_hover_filter =None 
def apply_global_hover_animations(app ):
    """Apply hover animation globally by installing an app-level event filter."""
    global _global_hover_filter 
    if _global_hover_filter is None :
        _global_hover_filter =GlobalHoverFilter()
    app.installEventFilter(_global_hover_filter )

def animate_scroll(scrollbar :QAbstractSlider, value :int, duration :int =300 ):
    """Smoothly animate scrolling to a specific value."""
    if hasattr(scrollbar ,"_scroll_anim"):
        anim =scrollbar._scroll_anim 
        anim.stop()
    else :
        anim =QPropertyAnimation(scrollbar, b"value",scrollbar )
        scrollbar._scroll_anim =anim 

    anim.setDuration(duration )
    anim.setStartValue(scrollbar.value())
    anim.setEndValue(value )
    anim.setEasingCurve(QEasingCurve.Type.OutQuad )
    anim.start()

class LoadingAnimation(QObject ):
    """A helper for text-based loading animations(e.g. 'Typing...', 'Typing.')"""
    def __init__(self, callback, base_text :str ="Loading",parent =None ):
        super().__init__(parent )
        self.callback =callback 
        self.base_text =base_text 
        self.dots =0 
        self.timer =QTimer(self )
        self.timer.timeout.connect(self.update_text )

    def start(self, interval :int =300 ):
        self.timer.start(interval )

    def stop(self ):
        self.timer.stop()

    def update_text(self ):
        self.dots =(self.dots +1 )%4 
        self.callback(f"{self.base_text}{'.' * self.dots}")
