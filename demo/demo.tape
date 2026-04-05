# srcleaks demo - scan for leaked source maps
Output demo/srcleaks-demo.gif

Set Shell "zsh"
Set FontSize 13
Set Width 1200
Set Height 800
Set Padding 10
Set Theme "Dracula"
Set TypingSpeed 40ms

# Show help
Type "srcleaks --help"
Enter
Sleep 3s

# Scan a clean npm package
Type "srcleaks left-pad"
Enter
Sleep 5s

# Scan a package with source maps — shows proof
Type "srcleaks socket.io-client"
Enter
Sleep 12s

# Scan a live website
Type "srcleaks https://sholuv.net"
Enter
Sleep 6s

# Done
Sleep 2s
