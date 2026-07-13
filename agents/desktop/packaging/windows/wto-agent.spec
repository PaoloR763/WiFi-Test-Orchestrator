from pathlib import Path

project = Path(SPECPATH).parents[1]
entry = project / "src" / "wto_desktop_agent" / "__main__.py"
package = project / "src" / "wto_desktop_agent"
datas = [
    (str(package / "contract_data"), "wto_desktop_agent/contract_data"),
    (
        str(package / "infrastructure" / "sqlite" / "versions"),
        "wto_desktop_agent/infrastructure/sqlite/versions",
    ),
    (
        str(package / "platforms" / "windows" / "scripts"),
        "wto_desktop_agent/platforms/windows/scripts",
    ),
]

analysis = Analysis(
    [str(entry)],
    pathex=[str(project / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "servicemanager",
        "win32api",
        "win32con",
        "win32cred",
        "win32event",
        "win32file",
        "win32job",
        "win32pipe",
        "win32security",
        "win32service",
        "win32serviceutil",
        "win32timezone",
    ],
    excludes=["secretstorage"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="wto-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="wto-agent",
)
