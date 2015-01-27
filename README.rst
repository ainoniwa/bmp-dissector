BGP Monitoring Protocol dissector
=================================
BGP Monitoring Protocol(BMP) dissector for wireshark written by lua.


Reference
=========
https://tools.ietf.org/id/draft-ietf-grow-bmp-07.txt


Usage
=====

Windows
-------
#. Comment out the "disable_lua=true" in "%WIRESHARK%\\init.lua". (Probably configured)
#. bmp.lua copy to "%WIRESHARK%\\plugins\\<version>\\" or "%APPDATA%\\Wireshark\\plugins\\".

e.g.: C:\\Users\\your-username\\AppData\\Roaming\\Wireshark\\plugins\\bmp.lua


Unix/Linux
----------
#. Commentout the "disable_lua=true" in /etc/wireshark/init.lua
#. bmp.lua copy to "/usr/share/wireshark/plugins", "/usr/local/share/wireshark/plugins" or "$HOME/.wireshark/plugins".

e.g.: /home/user/.wireshark/plugins/bmp.lua
