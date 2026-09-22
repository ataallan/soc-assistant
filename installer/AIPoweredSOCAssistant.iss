; AI-Powered SOC Assistant
; Customer artifact: dist\AIPoweredSOCAssistantSetup.exe
;
; Compile on Windows with Inno Setup 6:
;   powershell -ExecutionPolicy Bypass -File scripts\build_windows_installer.ps1
;
; Per-user install (no administrator prompt) under
; %LocalAppData%\AIPoweredSOCAssistant. One Desktop icon, a Start menu
; entry, and an uninstaller. The bootstrap downloads embeddable Python
; on the customer PC. This script does not embed mail passwords, API keys,
; or tunnel tokens.

#ifndef Payload
  #define Payload "..\dist\installer-payload"
#endif

#define AppName "AI-Powered SOC Assistant"
#define AppPublisher "Mun Cyber Technologies"
#define AppVersion "1.0.0"

[Setup]
AppId={{8F4C1A2E-6B37-4D91-9E5A-2C7F0B8D4A16}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppVerName={#AppName}
DefaultDirName={localappdata}\AIPoweredSOCAssistant
DefaultGroupName={#AppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=AIPoweredSOCAssistantSetup
SetupIconFile=..\static\img\ai-powered-soc-assistant.ico
UninstallDisplayIcon={app}\static\img\ai-powered-soc-assistant.ico
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=AI-Powered SOC Assistant Setup
VersionInfoProductName={#AppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#Payload}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\Launch AI-Powered SOC Assistant.bat"; WorkingDir: "{app}"; IconFilename: "{app}\static\img\ai-powered-soc-assistant.ico"; Comment: "{#AppName}"
Name: "{group}\{#AppName}"; Filename: "{app}\Launch AI-Powered SOC Assistant.bat"; WorkingDir: "{app}"; IconFilename: "{app}\static\img\ai-powered-soc-assistant.ico"; Comment: "{#AppName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\bootstrap_embedded_python.ps1"" -InstallDir ""{app}"""; WorkingDir: "{app}"; StatusMsg: "Preparing AI-Powered SOC Assistant. This can take a few minutes the first time."; Flags: waituntilterminated
Filename: "{app}\Launch AI-Powered SOC Assistant.bat"; Description: "Open AI-Powered SOC Assistant"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\runtime"

[Messages]
WelcomeLabel2=This installs AI-Powered SOC Assistant on this PC.%n%nSetup adds one Desktop icon named AI-Powered SOC Assistant, and a Start menu entry. The first launch starts the dashboard and opens the sign-in page in your browser. After that, use the Desktop icon.
FinishedLabel=AI-Powered SOC Assistant is installed.%n%nLeave the box below checked to open it now. The dashboard starts on this PC and the sign-in page opens in your browser.
