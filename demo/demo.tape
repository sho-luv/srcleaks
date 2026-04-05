# srcleaks demo - scan for leaked source maps
Output demo/srcleaks-demo.gif

Set Shell "zsh"
Set FontSize 14
Set Width 1200
Set Height 700
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

# Scan an npm package with source maps
Type "srcleaks rxjs"
Enter
Sleep 12s

# Scan a live website
Type "srcleaks https://sholuv.net"
Enter
Sleep 6s

# Mix and match - URL + npm packages
Type "srcleaks https://sholuv.net left-pad is-odd"
Enter
Sleep 10s

# Done
Sleep 2s
