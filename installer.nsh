; installer.nsh - Custom NSIS script for Bluebirds Secure Browser

!macro customInit
  ; Terminate any running instances of BluebirdsSecureBrowser before install or upgrade
  nsExec::Exec 'taskkill /F /IM BluebirdsSecureBrowser.exe /T'

  ; Clean up legacy / obsolete shortcuts before new installation begins
  ; 1. Current user context (legacy per-user NSIS installs)
  SetShellVarContext current
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser\Bluebirds Secure Browser.lnk"
  RMDir "$SMPROGRAMS\Bluebirds Secure Browser"
  DeleteRegKey HKCU "Software\Classes\bluebirds-sb"

  ; 2. All users context (legacy Inno Setup installs)
  SetShellVarContext all
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser\Bluebirds Secure Browser.lnk"
  RMDir "$SMPROGRAMS\Bluebirds Secure Browser"

  ; 3. Clean legacy Inno Setup uninstall registry entries
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\{2A895F29-CD9C-4C9D-A816-B0ED29584CEF}_is1"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\{2A895F29-CD9C-4C9D-A816-B0ED29584CEF}_is1"
!macroend

!macro customInstall
  ; Explicitly create shortcuts in All Users context (C:\ProgramData\Microsoft\Windows\Start Menu\Programs)
  SetShellVarContext all
  CreateShortCut "$SMPROGRAMS\Bluebirds Secure Browser.lnk" "$INSTDIR\BluebirdsSecureBrowser.exe" "" "$INSTDIR\BluebirdsSecureBrowser.exe" 0 "" "" "Bluebirds Secure Exam Browser"
  CreateShortCut "$DESKTOP\Bluebirds Secure Browser.lnk" "$INSTDIR\BluebirdsSecureBrowser.exe" "" "$INSTDIR\BluebirdsSecureBrowser.exe" 0 "" "" "Bluebirds Secure Exam Browser"

  ; Also create shortcuts in Current User context to guarantee Windows Search indexes it instantly
  SetShellVarContext current
  CreateShortCut "$SMPROGRAMS\Bluebirds Secure Browser.lnk" "$INSTDIR\BluebirdsSecureBrowser.exe" "" "$INSTDIR\BluebirdsSecureBrowser.exe" 0 "" "" "Bluebirds Secure Exam Browser"
  CreateShortCut "$DESKTOP\Bluebirds Secure Browser.lnk" "$INSTDIR\BluebirdsSecureBrowser.exe" "" "$INSTDIR\BluebirdsSecureBrowser.exe" 0 "" "" "Bluebirds Secure Exam Browser"
!macroend

!macro customUnInstall
  SetShellVarContext current
  Delete "$DESKTOP\Bluebirds Secure Browser.lnk"
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser.lnk"
  Delete "$SMPROGRAMS\BluebirdsSecureBrowser.lnk"
  DeleteRegKey HKCU "Software\Classes\bluebirds-sb"

  SetShellVarContext all
  Delete "$DESKTOP\Bluebirds Secure Browser.lnk"
  Delete "$DESKTOP\BluebirdsSecureBrowser.lnk"
  Delete "$SMPROGRAMS\Bluebirds Secure Browser.lnk"
  Delete "$SMPROGRAMS\BluebirdsSecureBrowser.lnk"
  DeleteRegKey HKLM "Software\Classes\bluebirds-sb"
!macroend
