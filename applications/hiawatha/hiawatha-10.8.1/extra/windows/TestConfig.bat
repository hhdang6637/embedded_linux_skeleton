@ECHO OFF

SET INSTALL_DIR=%~dp0
SET CYGWIN=nodosfilewarning

ECHO Wigwam:
"%INSTALL_DIR%program\wigwam.exe" -c "%INSTALL_DIR%config"
IF ERRORLEVEL 1 GOTO ERROR
ECHO.
ECHO Hiawatha:
"%INSTALL_DIR%program\hiawatha.exe" -k -c "%INSTALL_DIR%config"

:ERROR
ECHO.
PAUSE
