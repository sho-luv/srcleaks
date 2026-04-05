# srcleaks demo - scan for leaked source maps
Output demo/srcleaks-demo.gif

Set Shell "zsh"
Set FontSize 13
Set Width 1200
Set Height 800
Set Padding 10
Set Theme "Dracula"
Set TypingSpeed 40ms

# Scan a single npm package
Type "srcleaks socket.io-client"
Enter
Sleep 8s

# Scan an npm org
Type "srcleaks --org anthropic-ai"
Enter
Sleep 25s

# Scan a live website
Type "srcleaks https://sholuv.net"
Enter
Sleep 10s

# Done
Sleep 2s
