@ECHO OFF

"C:\Program Files\PHP7\php-cgi.exe" -b localhost:2005
IF ERRORLEVEL 1 PAUSE
