call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" x64
cl /I"..\include" /nologo /MT /O2 /c xyzcsp.c
rc /I"..\include" xyzcsp.rc
link /SUBSYSTEM:WINDOWS",5.0" /NODEFAULTLIB /DLL /DEF:xyzcsp.def /MACHINE:x86 /OUT:xyzcsp.dll xyzcsp.obj openssl.lib advapi32.lib kernel32.lib msvcrt.lib gdi32.lib user32.lib xyzcsp.res
copy xyzcsp.dll ..\testcsp\
rem copy xyzcsp.dll c:\windows\system32
