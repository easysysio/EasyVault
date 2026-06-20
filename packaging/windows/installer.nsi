; ============================================================================
; installer.nsi — Windows installer for EasyVault (built by makensis on CI)
;
; Built on Ubuntu via:
;   makensis -DVERSION=<v> -DINSTALLER_NAME=<name>.exe packaging/windows/installer.nsi
; makensis runs with the script's directory as the working dir, so File/OutFile
; paths are relative to packaging/windows/. The CI stages easyvault.exe,
; easyvault-service.exe (WinSW), config.toml.example and README.md there first.
;
; Installs EasyVault as a Windows service via the WinSW wrapper
; (easyvault-service.exe + easyvault-service.xml). Data (DB, TLS certs, config,
; logs) lives under %ProgramData%\EasyVault so it survives upgrades/uninstall.
; ============================================================================

!define APPNAME "EasyVault"
!define SVC "easyvault-service.exe"
!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifdef INSTALLER_NAME
  OutFile "${INSTALLER_NAME}"
!else
  OutFile "easyvault-setup.exe"
!endif

!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

Name "${APPNAME} ${VERSION}"
InstallDir "$PROGRAMFILES64\${APPNAME}"
RequestExecutionLevel admin
Unicode true

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

; ----------------------------------------------------------------------------
; Install — copy files, register + start the service, seed %ProgramData% data.
; ----------------------------------------------------------------------------
Section "Install"
  SetShellVarContext all      ; $APPDATA -> C:\ProgramData
  SetRegView 64

  ; On upgrade: stop + remove any existing service before overwriting files.
  IfFileExists "$INSTDIR\${SVC}" 0 +4
    DetailPrint "Stopping existing EasyVault service..."
    ExecWait '"$INSTDIR\${SVC}" stop'
    ExecWait '"$INSTDIR\${SVC}" uninstall'

  SetOutPath "$INSTDIR"
  File "easyvault.exe"
  File "easyvault-service.exe"
  File "easyvault-service.xml"
  File "config.toml.example"
  File "README.md"

  ; Data directory + a seeded config (only if not already present).
  CreateDirectory "$APPDATA\EasyVault"
  CreateDirectory "$APPDATA\EasyVault\logs"
  IfFileExists "$APPDATA\EasyVault\config.toml" +2 0
    CopyFiles /SILENT "$INSTDIR\config.toml.example" "$APPDATA\EasyVault\config.toml"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Start-menu shortcut that opens the dashboard in a browser.
  FileOpen $0 "$SMPROGRAMS\${APPNAME} Dashboard.url" w
  FileWrite $0 "[InternetShortcut]$\r$\n"
  FileWrite $0 "URL=http://localhost:8200$\r$\n"
  FileClose $0

  ; Register the service (Automatic start) and start it now.
  DetailPrint "Installing EasyVault service..."
  ExecWait '"$INSTDIR\${SVC}" install'
  ExecWait '"$INSTDIR\${SVC}" start'

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName"           "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion"        "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher"             "EasyVault"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString"       "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString"  "$\"$INSTDIR\uninstall.exe$\" /S"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
SectionEnd

; ----------------------------------------------------------------------------
; Uninstall — stop + remove the service, delete files. Data is left in place.
; ----------------------------------------------------------------------------
Section "Uninstall"
  SetShellVarContext all
  SetRegView 64

  ExecWait '"$INSTDIR\${SVC}" stop'
  ExecWait '"$INSTDIR\${SVC}" uninstall'

  Delete "$INSTDIR\easyvault.exe"
  Delete "$INSTDIR\easyvault-service.exe"
  Delete "$INSTDIR\easyvault-service.xml"
  Delete "$INSTDIR\easyvault-service.wrapper.log"
  Delete "$INSTDIR\config.toml.example"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${APPNAME} Dashboard.url"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINSTKEY}"
  ; Note: %ProgramData%\EasyVault (database, certs, config, logs) is preserved.
SectionEnd
