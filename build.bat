@echo off
@REM --windows-icon-from-ico=ICON.ico
python -m nuitka --onefile --standalone --enable-plugin=pyqt5 --remove-output --include-data-files=style.qss=style.qss --windows-console-mode=disable --output-dir=dist feedstream.py
pause