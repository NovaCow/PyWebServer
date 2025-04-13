# PyWebServer

## Installing
Installing and running PyWebServer is very simple.  
Assuming you're running Linux:
```bash
git clone https://git.novacow.ch/Nova/PyWebServer.git
cd ./PyWebServer/
```
Windows users, make sure you have installed Git, from there:
```powershell
git clone https://git.novacow.ch/Nova/PyWebServer.git
Set-Location .\PyWebServer\
```
From here, you should check from what directory you want to store the content in.  
In this example, we'll use `./html/` (or `.\html\` for Windows users) from the perspective of the PyWebServer root dir.  
To create this directory, do this:
```bash
mkdir ./html/
```
(This applies to both Windows and Linux)  
Then, open `pywebsrv.conf` in your favorite text editor and change the `directory` key to the full path to the `./html/` you just created.  
After that, put your files in and run this:
Linux:
```bash
python3 /path/to/pywebsrv.py
```
Windows:
```powershell
# If you have installed Python via the Microsoft Store:
python3 \path\to\pywebsrv.py
# Via the python.org website:
py \path\to\pywebsrv.py
```

## SSL Support
Currently PyWebServer warns about AutoCertGen not being installed. AutoCertGen currently is very unstable at the moment, 
