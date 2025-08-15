@echo off

if exist "C:\Program Files\7-Zip\7z.exe" goto SetAssoc
Goto Exit
:SetAssoc
assoc .001=7-Zip.001
assoc .7z=7-Zip.7z
assoc .arj=7-Zip.arj
assoc .bz2=7-Zip.bz2
assoc .bzip2=7-Zip.bzip2
assoc .cab=7-Zip.cab
assoc .cpio=7-Zip.cpio
assoc .deb=7-Zip.deb
assoc .gz=7-Zip.gz
assoc .gzip=7-Zip.gzip
assoc .iso=7-Zip.iso
assoc .lha=7-Zip.lha
assoc .lzh=7-Zip.lzh
assoc .rar=7-Zip.rar
assoc .rpm=7-Zip.rpm
assoc .split=7-Zip.split
assoc .swm=7-Zip.swm
assoc .tar=7-Zip.tar
assoc .taz=7-Zip.taz
assoc .tbz=7-Zip.tbz
assoc .tbz2=7-Zip.tbz2
assoc .tgz=7-Zip.tgz
assoc .tpz=7-Zip.tpz
assoc .wim=7-Zip.wim
assoc .z=7-Zip.z
assoc .zip=7-Zip.zip
assoc .dmg=7-Zip.dmg
assoc .hfs=7-Zip.hfs
assoc .lzma=7-Zip.lzma
assoc .xar=7-Zip.xar
assoc .vhd=7-Zip.vhd
assoc .vhdx=7-Zip.vhdx
assoc .esd=7-Zip.esd
assoc .fat=7-Zip.fat
assoc .ntfs=7-Zip.ntfs
assoc .squashfs=7-Zip.squashfs
assoc .apfs=7-Zip.apfs
assoc .xz=7-Zip.xz
assoc .txz=7-Zip.txz
assoc .zst=7-Zip.zst
assoc .tzst=7-Zip.tzst
ftype 7-Zip.001="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.001" /ve /d "001 Archive" /f
reg add "HKCR\7-Zip.001\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,0" /f
ftype 7-Zip.7z="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.7z" /ve /d "7z Archive" /f
reg add "HKCR\7-Zip.7z\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,0" /f
ftype 7-Zip.arj="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.arj" /ve /d "arj Archive" /f
reg add "HKCR\7-Zip.arj\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,4" /f
ftype 7-Zip.bz2="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.bz2" /ve /d "bz2 Archive" /f
reg add "HKCR\7-Zip.bz2\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,2" /f
ftype 7-Zip.bzip2="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.bzip2" /ve /d "bzip2 Archive" /f
reg add "HKCR\7-Zip.bzip2\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,2" /f
ftype 7-Zip.cab="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.cab" /ve /d "cab Archive" /f
reg add "HKCR\7-Zip.cab\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,7" /f
ftype 7-Zip.cpio="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.cpio" /ve /d "cpio Archive" /f
reg add "HKCR\7-Zip.cpio\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,12" /f
ftype 7-Zip.deb="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.deb" /ve /d "deb Archive" /f
reg add "HKCR\7-Zip.deb\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,11" /f
ftype 7-Zip.gz="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.gz" /ve /d "gz Archive" /f
reg add "HKCR\7-Zip.gz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,14" /f
ftype 7-Zip.gzip="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.gzip" /ve /d "gzip Archive" /f
reg add "HKCR\7-Zip.gzip\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,14" /f
ftype 7-Zip.iso="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.iso" /ve /d "iso Archive" /f
reg add "HKCR\7-Zip.iso\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,8" /f
ftype 7-Zip.lha="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.lha" /ve /d "lha Archive" /f
reg add "HKCR\7-Zip.lha\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,6" /f
ftype 7-Zip.lzh="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.lzh" /ve /d "lzh Archive" /f
reg add "HKCR\7-Zip.lzh\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,6" /f
ftype 7-Zip.rar="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.rar" /ve /d "rar Archive" /f
reg add "HKCR\7-Zip.rar\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,3" /f
ftype 7-Zip.rpm="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.rpm" /ve /d "rpm Archive" /f
reg add "HKCR\7-Zip.rpm\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,10" /f
ftype 7-Zip.split="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.split" /ve /d "split Archive" /f
reg add "HKCR\7-Zip.split\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,9" /f
ftype 7-Zip.swm="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.swm" /ve /d "swm Archive" /f
reg add "HKCR\7-Zip.swm\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,15" /f
ftype 7-Zip.tar="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.tar" /ve /d "tar Archive" /f
reg add "HKCR\7-Zip.tar\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,13" /f
ftype 7-Zip.taz="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.taz" /ve /d "taz Archive" /f
reg add "HKCR\7-Zip.taz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,5" /f
ftype 7-Zip.tbz="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.tbz" /ve /d "tbz Archive" /f
reg add "HKCR\7-Zip.tbz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,2" /f
ftype 7-Zip.tbz2="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.tbz2" /ve /d "tbz2 Archive" /f
reg add "HKCR\7-Zip.tbz2\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,2" /f
ftype 7-Zip.tgz="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.tgz" /ve /d "tgz Archive" /f
reg add "HKCR\7-Zip.tgz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,14" /f
ftype 7-Zip.tpz="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.tpz" /ve /d "tpz Archive" /f
reg add "HKCR\7-Zip.tpz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,14" /f
ftype 7-Zip.wim="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.wim" /ve /d "wim Archive" /f
reg add "HKCR\7-Zip.wim\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,15" /f
ftype 7-Zip.z="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.z" /ve /d "z Archive" /f
reg add "HKCR\7-Zip.z\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,5" /f
ftype 7-Zip.zip="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.zip" /ve /d "zip Archive" /f
reg add "HKCR\7-Zip.zip\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,1" /f
ftype 7-Zip.dmg="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.dmg" /ve /d "dmg Archive" /f
reg add "HKCR\7-Zip.dmg\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,17" /f
ftype 7-Zip.hfs="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.hfs" /ve /d "hfs Archive" /f
reg add "HKCR\7-Zip.hfs\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,18" /f
ftype 7-Zip.lzma="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.lzma" /ve /d "lzma Archive" /f
reg add "HKCR\7-Zip.lzma\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,16" /f
ftype 7-Zip.xar="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.xar" /ve /d "xar Archive" /f
reg add "HKCR\7-Zip.xar\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,19" /f
ftype 7-Zip.vhd="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.vhd" /ve /d "vhd Archive" /f
reg add "HKCR\7-Zip.vhd\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,20" /f
ftype 7-Zip.vhdx="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.vhdx" /ve /d "vhdx Archive" /f
reg add "HKCR\7-Zip.vhdx\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,21" /f
ftype 7-Zip.esd="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.esd" /ve /d "esd Archive" /f
reg add "HKCR\7-Zip.esd\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,22" /f
ftype 7-Zip.fat="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.fat" /ve /d "fat Archive" /f
reg add "HKCR\7-Zip.fat\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,23" /f
ftype 7-Zip.ntfs="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.ntfs" /ve /d "ntfs Archive" /f
reg add "HKCR\7-Zip.ntfs\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,24" /f
ftype 7-Zip.squashfs="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.squashfs" /ve /d "squashfs Archive" /f
reg add "HKCR\7-Zip.squashfs\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,25" /f
ftype 7-Zip.apfs="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.apfs" /ve /d "apfs Archive" /f
reg add "HKCR\7-Zip.apfs\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,26" /f
ftype 7-Zip.xz="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.xz" /ve /d "xz Archive" /f
reg add "HKCR\7-Zip.xz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,27" /f
ftype 7-Zip.vhd="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.txz" /ve /d "txz Archive" /f
reg add "HKCR\7-Zip.txz\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,28" /f
ftype 7-Zip.zst="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.zst" /ve /d "zst Archive" /f
reg add "HKCR\7-Zip.zst\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,28" /f
ftype 7-Zip.tzst="%programfiles%\7-Zip\7zFM.exe" "%%1"
reg add "HKCR\7-Zip.tzst" /ve /d "tzst Archive" /f
reg add "HKCR\7-Zip.tzst\DefaultIcon" /ve /d "%programfiles%\7-Zip\7z.dll,28" /f
:Exit