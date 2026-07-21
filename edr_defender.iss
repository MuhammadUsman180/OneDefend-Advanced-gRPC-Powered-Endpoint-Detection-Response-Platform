; --- INNO SETUP SCRIPT FOR EDR DEFENDER ---
[Setup]
AppName=EDR Defender
AppVersion=1.2.8
DefaultDirName=C:\ProgramData\EDR_Defender
OutputBaseFilename=EDR Defender installer
SetupIconFile=C:\MyEDR\shield.ico
DefaultGroupName=EDR Defender
UninstallDisplayIcon={app}\agent.exe
Compression=lzma
SolidCompression=yes
; Require Admin for installation
PrivilegesRequired=admin
OutputDir=userdocs:Inno Setup Outputs


[Files]
; The actual program (Service and UI)
Source: "C:\MyEDR\dist\agent.exe"; DestDir: "{app}"; Flags: ignoreversion
; The tools and security files
Source: "C:\MyEDR\nssm.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\MyEDR\server.crt"; DestDir: "{app}"; Flags: ignoreversion
; The YARA rules folder
Source: "C:\MyEDR\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs
Source: "C:\MyEDR\shield.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Create the Desktop Shortcut with the --show-ui flag
;Name: "{commondesktop}\EDR Defender"; Filename: "{app}\agent.exe"; Parameters: "--show-ui"; WorkingDir: "{app}"
Name: "{commondesktop}\EDR Defender"; Filename: "{app}\agent.exe"; Parameters: "--show-ui"; WorkingDir: "{app}"; IconFilename: "{app}\shield.ico"
[Run]
; 1. Install the Service via NSSM
Filename: "{app}\nssm.exe"; Parameters: "install MyEDR_Agent ""{app}\agent.exe"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set MyEDR_Agent AppDirectory ""{app}"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set MyEDR_Agent DisplayName ""EDR Defender Agent"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set MyEDR_Agent AppExit 0 Exit"; Flags: runhidden

; 2. Configure Recovery (Restart on crash)
;Filename: "{cmd}"; Parameters: "/c sc.exe failure MyEDR_Agent reset= 86400 actions= restart/5000/restart/5000"; Flags: runhidden

; 3. Start the Service
Filename: "{cmd}"; Parameters: "/c net start MyEDR_Agent"; Flags: runhidden

; 4. Apply the Iron Shield (Gray out Stop button)
; Using the exact SDDL from your friend's code
Filename: "{cmd}"; Parameters: "/c sc.exe sdset MyEDR_Agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;AU)"; Flags: runhidden

; --- Add this to the end of the [Run] section in your Inno Setup script ---
Filename: "{cmd}"; Parameters: "/c powershell.exe -Command ""$acl = Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\MyEDR_Agent'; $adminDeny = New-Object System.Security.AccessControl.RegistryAccessRule('Administrators','SetValue,Delete','Deny'); $acl.AddAccessRule($adminDeny); Set-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\MyEDR_Agent' $acl"""; Flags: runhidden

[UninstallRun]
; 1. UNLOCK REGISTRY FIRST so the service can be removed
Filename: "{cmd}"; Parameters: "/c powershell.exe -Command ""$acl = Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\MyEDR_Agent'; $acl.SetAccessRuleProtection($false, $false); Set-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\MyEDR_Agent' $acl"""; Flags: runhidden

; Cleanup: Unlock, Stop, and Remove Service during uninstallation
Filename: "{cmd}"; Parameters: "/c sc.exe sdset MyEDR_Agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "stop MyEDR_Agent"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "remove MyEDR_Agent confirm"; Flags: runhidden
[Code]
// --- FIX: Using TForm instead of TSetupForm to avoid Resource Errors ---
var
  UninstallPwdEdit: TEdit;

function InitializeUninstall(): Boolean;
var
  PwdForm: TForm;
  PromptLabel: TLabel;
  OkButton, CancelButton: TButton;
begin
  Result := False;

  // Create a standard Windows Form
  PwdForm := TForm.Create(nil);
  try
    with PwdForm do
    begin
      ClientWidth := ScaleX(400);
      ClientHeight := ScaleY(180);
      Caption := 'EDR Defender - Uninstall Protection';
      Position := poScreenCenter;
      // Ensure it stays on top
      FormStyle := fsStayOnTop;
    end;

    PromptLabel := TLabel.Create(PwdForm);
    with PromptLabel do
    begin
      Parent := PwdForm;
      Left := ScaleX(20);
      Top := ScaleY(20);
      Width := PwdForm.ClientWidth - ScaleX(40);
      Height := ScaleY(40);
      AutoSize := False;
      WordWrap := True;
      Caption := 'Enter the Administrator Authorization Key to proceed with uninstallation:';
    end;

    UninstallPwdEdit := TEdit.Create(PwdForm);
    with UninstallPwdEdit do
    begin
      Parent := PwdForm;
      Left := ScaleX(20);
      Top := ScaleY(70);
      Width := PwdForm.ClientWidth - ScaleX(40);
      PasswordChar := '*';
    end;

    OkButton := TButton.Create(PwdForm);
    with OkButton do
    begin
      Parent := PwdForm;
      Caption := 'OK';
      Default := True;
      Left := ScaleX(210);
      Top := ScaleY(120);
      Width := ScaleX(80);
      Height := ScaleY(30);
      ModalResult := mrOk;
    end;

    CancelButton := TButton.Create(PwdForm);
    with CancelButton do
    begin
      Parent := PwdForm;
      Caption := 'Cancel';
      Left := ScaleX(300);
      Top := ScaleY(120);
      Width := ScaleX(80);
      Height := ScaleY(30);
      ModalResult := mrCancel;
    end;

    if PwdForm.ShowModal() = mrOk then
    begin
      if UninstallPwdEdit.Text = '12121234@Usman' then
        Result := True
      else
        MsgBox('INVALID KEY. Uninstallation blocked.', mbCriticalError, MB_OK);
    end;
  finally
    PwdForm.Free();
  end;
end;