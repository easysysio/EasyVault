; ============================================================================
; installer.nsi — Windows installer for EasyVault (built by makensis in CI)
;
; Invoked from the repository root, e.g.:
;   makensis /DVERSION=0.1.0 packaging\windows\installer.nsi
; Produces easyvault-<VERSION>-setup.exe in the working directory.
; ============================================================================

!define APPNAME "EasyVault"
!define COMPANY  "EasyVault"
!ifndef VERSION
  !define VERSION "0.0.0"
!endif

!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

Name "${APPNAME} ${VERSION}"
OutFile "easyvault-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel admin
Unicode true

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

; ----------------------------------------------------------------------------
; Install — copy the binary + sample config, register uninstaller & shortcut.
; ----------------------------------------------------------------------------
Section "Install"
  SetOutPath "$INSTDIR"
  File "target\release\easyvault.exe"
  File "config.toml.example"
  File "README.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\easyvault.exe"

  WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName"     "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher"       "${COMPANY}"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
SectionEnd

; ----------------------------------------------------------------------------
; Uninstall — remove files, shortcut and registry keys.
; ----------------------------------------------------------------------------
Section "Uninstall"
  Delete "$INSTDIR\easyvault.exe"
  Delete "$INSTDIR\config.toml.example"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "Software\${APPNAME}"
SectionEnd
