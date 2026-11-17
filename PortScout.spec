# PyInstaller folder build:  pyinstaller --noconfirm PortScout.spec
a = Analysis(["main.py"], datas=[("data/*", "data")], excludes=["tkinter", "pytest"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="PortScout", console=False,
          icon="data/icon.ico")
coll = COLLECT(exe, a.binaries, a.datas, name="PortScout")
