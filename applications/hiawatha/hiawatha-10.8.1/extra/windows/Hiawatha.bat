@ECHO OFF

SET INSTALL_DIR=%~dp0
SET CYGWIN=nodosfilewarning

"%INSTALL_DIR%program\wigwam.exe" -q -c "%INSTALL_DIR%config"
IF ERRORLEVEL 1 GOTO ERROR
"%INSTALL_DIR%program\hiawatha.exe" -d -c "%INSTALL_DIR%config"
IF ERRORLEVEL 1 GOTO ERROR
GOTO END

:ERROR
PAUSE

:END
