# PyWebServer

## GitHub
The upstream of this project is on my own [Gitea instance](https://git.novacow.ch/Nova/PyWebServer/).  
Because of that I'll mostly reply to issues and PRs there, you can submit issues and PRs on GitHub, but it might take longer before I read it.

## Installing
### The little tiny easier route
Installing and running PyWebServer is very simple.  
First off, download the latest release from the 'Releases' tab, choose the Zip variant if unsure.  
When it's done downloading, unpack the files in a directory of choice, for the purpose of this README, 
I've chosen `./pywebserver/` (for Windows: `.\pywebserver\`).  
From there, open up your favorite text editor and open the file `pywebsrv.conf` in the directory you unpacked PyWebServer.  
In there, you should see this somewhere:
```
# Here you choose what directory PyWebServer looks in for files.
directory:<Enter directory here>
```
After the colon, enter your directory where you have your website stored.  
After that, make sure you have installed Python. Here's how you can install Python:  
Linux:
```bash
sudo apt install python3  # Debian / Ubuntu
sudo dnf install python3  # Fedora / Nobara
sudo pacman -S python3  # Arch and derivatives.
```
macOS:
```bash
brew install python3
```
Windows:
```powershell
# You can change the `3.12` with whatever version you want/need.
winget install -e --id Python.Python.3.12 --scope machine
```
Then, in the terminal window you have open, go to the directory you unpacked PyWebServer and type this:
```
python3 ./pywebsrv.py
# For Windows users, if the above command doesn't work, try this:
py ./pywebsrv.py
```
And there you go! You've now set up PyWebServer!

### The little tiny harder route
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
Then, open `pywebsrv.conf` in your favorite text editor and change the `directory` key to the full path where your files are stored.  
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
PyWebServer supports SSL/TLS for authentication via HTTPS. In the config file, you should enable the HTTPS port. After that you need to create the certificate.  
Currently PyWebServer looks for the `cert.pem` and the `key.pem` files in the root directory of the installation.  

## HTTP support
Currently PyWebServer only supports HTTP/1.1, this is very unlikely to change, as most of the modern web today still uses HTTP/1.1.  
For methods PyWebServer only supports `GET`, this is being reworked though, check issue [#3](https://git.novacow.ch/Nova/PyWebServer/issues/3) for progress.

## Files support
Unlike other small web servers, PyWebServer has full support for binary files being sent and received (once that logic is put in) over HTTP(S).

## Support
PyWebServer will follow a standard support scheme.
### 1.x
For every 1.x version there will be support until 2 newer versions come out.
So that means that 1.0 will still be supported when 1.1 comes out, but no longer be supported when 1.2 comes out.
### 2.x
I am planning on releasing a 2.x version with will have a lot more advanced features, like nginx's server block emulation amongst other things.
When 2.0 will come out, 1.x will be developed further, but 2.0 will be the main focus.
