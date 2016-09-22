Windbg Script Encoder For Metasploit
======================================

From an idea at http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html

Bypass various kinds of protections, AV, application whitelisting etc by running your 
shellcode in another process. This encoder will give up a cdb script to run to insert
your shellcode in another process.

** INSTALLATION **

cp windbg.rb to same path in your metasploit install

** USAGE **

The following example will pop calc from a notepad process:

msfvenom  -p windows/x64/exec -e generic/windbg EXITFUNC=thread CMD=calc.exe > calc.wds
cdb.exe -cf calc.wds -o notepad.exe



