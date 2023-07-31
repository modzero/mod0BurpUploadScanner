@echo off

REM Command 1: java -jar 'C:\Program Files\jython2.7.2\jython.jar' -m compileall .
set "JythonPath=C:\Program Files\jython2.7.2\jython.jar"
java -jar "%JythonPath%" -m compileall .

REM Command 2: 'C:\Program Files\Java\jdk-17.0.2\bin\jar.exe' cf uploadscanner.jar .
set "JavaPath=C:\Program Files\Java\jdk-17.0.2\bin\jar.exe"
set "OutputJar=uploadscanner.jar"
"%JavaPath%" cf %OutputJar% .
