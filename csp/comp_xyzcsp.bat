call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" x64
cl /I"..\include" /I"..\sdkinc" /I"..\openssl\engines\ccgost" /I"..\openssl\inc32" /nologo /MT /O2 /c xyzcsp.c
rc /I"..\include" /I"..\sdkinc" /I"..\openssl\engines\ccgost" /I"..\openssl\inc32" xyzcsp.rc
link /SUBSYSTEM:WINDOWS",5.0" /NODEFAULTLIB /DLL /DEF:xyzcsp.def /MACHINE:x64 /OUT:xyzcsp.dll xyzcsp.obj ..\openssl\out32dll\4758cca.lib ..\openssl\out32dll\aep.lib ..\openssl\out32dll\atalla.lib ..\openssl\out32dll\capi.lib ..\openssl\out32dll\chil.lib ..\openssl\out32dll\cswift.lib ..\openssl\out32dll\gmp.lib ..\openssl\out32dll\gost.lib ..\openssl\out32dll\libeay32.lib ..\openssl\out32dll\nuron.lib ..\openssl\out32dll\padlock.lib ..\openssl\out32dll\ssleay32.lib ..\openssl\out32dll\sureware.lib ..\openssl\out32dll\ubsec.lib ..\openssl\tmp32dll\gosthash.obj ..\openssl\tmp32dll\gost2001.obj ..\openssl\tmp32dll\gost_sign.obj ..\openssl\tmp32dll\gost89.obj ..\openssl\tmp32dll\e_gost_err.obj ..\openssl\tmp32dll\gost_params.obj advapi32.lib kernel32.lib msvcrt.lib gdi32.lib user32.lib xyzcsp.res
copy xyzcsp.dll ..\testcsp\
rem copy xyzcsp.dll c:\windows\system32
