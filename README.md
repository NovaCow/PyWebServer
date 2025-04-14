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
Currently PyWebServer warns about AutoCertGen not being installed. AutoCertGen currently is very unstable at the moment, and therefore is not available for download.  
PyWebServer supports SSL/TLS for authentication via HTTPS. In the config file, you should enable the HTTPS port. After that you need to create the certificate.  
Currently PyWebServer looks for the `cert.pem` and the `key.pem` files in the root directory of the installation.  
PyWebServer comes with a test certificate, this certificate is self-signed, but doesn't have a matching issuer and subject. This is to prevent people from using it in production, even if they have disabled warnings of self-signed certificates.  

## HTTP support
Currently PyWebServer only supports HTTP/1.1, this is very unlikely to change, as most of the modern web today still uses HTTP/1.1.  
For methods PyWebServer only supports `GET`, this is being reworked though, check issue [#3](https://git.novacow.ch/Nova/PyWebServer/issues/3) for progress.

## Files support
Unlike other small web servers, PyWebServer has full support for binary files being sent and received (once that logic is put in) over HTTP.

## Support
PyWebServer will follow a standard support scheme.
### 1.x
For every 1.x version there will be support until 2 newer versions come out.
So that means that 1.0 will still be supported when 1.1 comes out, but no longer be supported when 1.2 comes out.
### 2.x
I am planning on releasing a 2.x version with will have a lot more advanced features, like nginx's server block emulation amongst other things.
When 2.0 will come out, the last version of 1.x will be supported for a while longer, but no new features will be added.
