import sys 
from PyQt6.QtWidgets import QCheckBox 
from PyQt6.QtCore import Qt, QPropertyAnimation, QRectF, QPoint, QEasingCurve, QSize, pyqtProperty 
from PyQt6.QtGui import QPainter, QColor, QPainterPath 

import config 

class AnimatedToggle(QCheckBox ):
    """
    A custom, smooth, animated toggle switch.
    Replaces the standard QCheckBox visual entirely.
    """
    def __init__(self, parent =None ):
        super().__init__(parent )
        self.setCursor(Qt.CursorShape.PointingHandCursor )

        #colors
        self._bg_color_off =QColor("#bdc3c7")
        self._bg_color_on =QColor(config.COLOR_PRIMARY )
        self._circle_color =QColor("#ffffff")

        self._circle_position =3 

        self.animation =QPropertyAnimation(self, b"circle_position",self )
        self.animation.setEasingCurve(QEasingCurve.Type.InOutSine )
        self.animation.setDuration(250 )

        self.stateChanged.connect(self.start_transition )

    @pyqtProperty(float )
    def circle_position(self ):
        return self._circle_position 

    @circle_position.setter 
    def circle_position(self, pos ):
        self._circle_position =pos 
        self.update()

    def start_transition(self, value ):
        self.animation.stop()
        if value :
            self.animation.setEndValue(23 )
        else :
            self.animation.setEndValue(3 )
        self.animation.start()

    def hitButton(self, pos :QPoint ):
        return self.contentsRect().contains(pos )

    def sizeHint(self ):
        return QSize(44, 24 )

    def paintEvent(self, event ):
        p =QPainter(self )
        p.setRenderHint(QPainter.RenderHint.Antialiasing )

        p.setPen(Qt.PenStyle.NoPen )

        #determine background color based on state and animation position
        rect =QRectF(0, 0 ,self.width(),self.height())

        #interpolate color slightly during animation or just swap based on direction
        bg_col =self._bg_color_on if self.isChecked()else self._bg_color_off 

        path =QPainterPath()
        path.addRoundedRect(rect, self.height()/2, self.height()/2 )
        p.fillPath(path, bg_col )

        #draw the circle
        p.setBrush(self._circle_color )
        circle_rect =QRectF(self._circle_position, 3 ,18, 18 )
        p.drawEllipse(circle_rect )
        p.end()
