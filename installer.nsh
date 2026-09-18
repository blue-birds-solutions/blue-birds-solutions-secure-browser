; installer.nsh - Custom NSIS cleanup script for Bluebirds Secure Browser
; Clean up legacy Inno Setup artifacts, old desktop shortcuts, and stale registry entries

!macro customInit
  ; Terminate any running instances of BluebirdsSecureBrowser before install or upgrade
  nsExec::Exec 'taskkill /F /IM BluebirdsSecureBrowser.exe /T'
!macroend

!macro customInstall
  ; 1. Clean shortcuts from Current User context (legacy per-user NSIS installs)
  SetShellVarContext current
  Delete "$DESKTOP\Bluebirds Secure Browser.lnk"
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser\Bluebirds Secure Browser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser.lnk"
  RMDir "$SMPROGRAMS\Bluebirds Secure Browser"
  DeleteRegKey HKCU "Software\Classes\bluebirds-sb"

  ; 2. Clean shortcuts from All Users / Public context (legacy Inno Setup installs)
  SetShellVarContext all
  Delete "$DESKTOP\Bluebirds Secure Browser.lnk"
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser\Bluebirds Secure Browser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser.lnk"
  RMDir "$SMPROGRAMS\Bluebirds Secure Browser"
  DeleteRegKey HKLM "Software\Classes\bluebirds-sb"

  ; 3. Clean legacy Inno Setup uninstall registry entry if present
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{2A895F29-CD9C-4C9D-A816-B0ED29584CEF}_is1"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\{2A895F29-CD9C-4C9D-A816-B0ED29584CEF}_is1"
!macroend

!macro customUnInstall
  SetShellVarContext current
  Delete "$DESKTOP\Bluebirds Secure Browser.lnk"
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  DeleteRegKey HKCU "Software\Classes\bluebirds-sb"

  SetShellVarContext all
  Delete "$DESKTOP\Bluebirds Secure Browser.lnk"
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  DeleteRegKey HKLM "Software\Classes\bluebirds-sb"
!macroend
