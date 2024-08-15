# LuaFFI Code execution

To be used with titles that support FFI in their LUA engine

f.e.

- Warhammer Vermintide
- Warhammer Vermintide 2

Tools:

- XblContainerReader: <https://github.com/LukeFZ/XblContainerReader>

## How To

- Edit `stage1.lua` with your PC's IP/PORT
- Overwrite the savegame of your choice with the edited version of `stage1.lua`
- Edit `stage2.lua` and serve it via netcat(TCP) on the configured IP/Port that was configured in `stage1` 

Example

```
# Note: -w <seconds> will cleanly close the socket after all data (aka. stage2) was sent to the client
cat stage2.lua | nc -w 1 -lvp 8123
```

Also open another socket that stage2 can use

```
nc -lvp 8124
```

- Start the game / have savegame loaded
- Profit

PS: The testWindows variable is very useful to set when you wanna dry-run on windows first!

For dumping games, edit the target XVC path in stage2.lua, then run a *Twodump* release. These can be found in the Releases tab.

Windows LuaJIT: https://github.com/luapower/luajit/tree/master/bin/mingw64 (only need exe and dll)

## Credits

- TitleOS
- ihatecompvir
- LukeFZ
- onebawbag
- Shadow LAG
- Team XboxOneResearch
- msixvc
- InvoxiPlayGames, for their initial [OneDumpGame](https://github.com/invoxiplaygames/onedumpgame) dumping solution the dumping code in this repo is based off of. 
