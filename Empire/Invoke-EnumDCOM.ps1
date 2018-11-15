function Invoke-DCOMrade {
    <#
    .SYNOPSIS
    Powershell script for checking possibly vulnerable DCOM applications.

    .DESCRIPTION
    This script is able to check if the external RPC allow Firewall rule is present (optional), enumerate the DCOM applications and check the Methods / Properties of the 
    DCOM applications for possible vulnerabilities. 

    The first check is the RPC check which verifies whether or not RPC connections from external are allowed.
    The RPC connection can be recognized in the Windows Firewall with the following query:
    v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC

    The Windows registry holds this value at the following location:
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules

    If the rule is not present it is added with the following Powershell oneliner:
    New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules -Name RPCtest -PropertyType String -Value 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|App=any|Svc=*|Name=Allow RPC IN|Desc=custom RPC allow|'

    After adding the RPC firewall rule the script will enumerate the DCOM applications present on the machine and verify which CLSID belongs to which DCOM application.

    The DCOM applications will get instantiated by the script and the amount of MemberTypes present will be checked, the DCOM applications might be interesting if it doesn't
    hold the same as the default amount of MemberTypes (this is checked by counting the amount of MemberTypes when instantiating the default CLSID of "Shortcut") and holds more
    MemberTypes than 0.

    .PARAMETER ComputerName
    The ComputerName of the victim machine

    .PARAMETER User
    The Username of the victim

    .PARAMETER os
    The operating system of the target machine

    .PARAMETER interactive
    Set this to $True if you want an interactive session with the machine

    .PARAMETER Blacklist
    Set this to $True if you want to create a custom Blacklist out of the CLSIDs that cannot be instantiated

    .EXAMPLE
    PS > Check-DCOMApps.ps1 -ComputerName victim -User alice -os win10
    Use this above command and parameters to start a non-interactive session when the target system is a Windows 10 machine

    PS > Check-DCOMApps.ps1 -ComputerName victim -User alice -os win10 -interactive $True
    Use this command and parameters to start a interactive session when the target system is a Windows 10 machine

    PS > Check-DCOMApps.ps1 -ComputerName victim -User alive -os win10 -Blacklist $True
    Use this command and parameters to start a non-interactive session that writes a custom BLSID based on CLSIDs that could not get instantiated
    This is a good option when in a Windows Domain where the machines have the same software installed (avoids unnecessary hanging of the script)

    .LINK
    https://github.com/sud0woodo

    .NOTES 
    DISCLAIMER: I am not a developer, this code is probably not as efficient as it could have been. 
    I am not responsible for the usage and outcomes of this tool, this tool was created for educational purposes.

    Access to the local/Domain administrator account on the target machine is needed to enable PSRemoting and check/change the Firewall rules.
    To enable the features needed, execute the following commands:

    PS > Enable-PSRemoting -SkipNetworkProfileCheck -Force

    Author: Axel Boesenach
    #>

    # Assign arguments to parameters
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [String]$ComputerName,

        [Parameter(Mandatory=$True,Position=2)]
        [String]$User,

        [Parameter(Mandatory=$True,Position=3)]
        [ValidateSet("win7","win10","win2k12","win2k16")]
        [String]$OS,

        [Parameter(Mandatory=$False,Position=4)]
        [String]$Domain,

        [Parameter(Mandatory=$False,Position=5)]
        [Boolean]$Blacklist
        )

    $ResultDir = (Get-Item -Path ".\").FullName + "\$ComputerName"

    $CurrentDate = Get-Date

    # Define filenames to write to
    $DCOMApplicationsFile = "DCOM_Applications_$ComputerName.txt"
    $LaunchPermissionFile = "DCOM_DefaultLaunchPermissions_$ComputerName.txt"
    $MemberTypeCountFile = "CLSID_MemberTypeCount_$ComputerName.txt"
    $CLSIDFile = "DCOM_CLSID_$ComputerName.txt"

    # Create two blacklists: Windows 7 and Windows 10
    $Win7BlackList = @"
    {35b1d3bb-2d4e-4a7c-9af0-f2f677af7c30}
    {375ff002-dd27-11d9-8f9c-0002b3988e81}
    {3B191048-B0AD-4CFE-902C-F51140AA77ED}
    {45597c98-80f6-4549-84ff-752cf55e2d29}
    {682159d9-c321-47ca-b3f1-30e36b2ec8b9}
    {69F9CB25-25E2-4BE1-AB8F-07AA7CB535E8}
    {75dff2b7-6936-4c06-a8bb-676a7b00b24b}
    {7AB36653-1796-484B-BDFA-E74F1DB7C1DC}
    {A24BCC4A-448D-41CA-92BB-3DC15D81C16C}
    {A4DDCA2B-E73C-40C5-83B1-9F40269D0B0D}
    {A49211A1-022F-43D7-BC55-D787C66ACF8E}
    {cdc32574-7521-4124-90c3-8d5605a34933}
    {ceff45ee-c862-41de-aee2-a022c81eda92}
    {ed1d0fdf-4414-470a-a56d-cfb68623fc58}
"@
    $Win10BlackList = @"
    {00021401-0000-0000-C000-000000000046}
    {03E15B2E-CCA6-451C-8FB0-1E2EE37A27DD}
    {0358b920-0ac7-461f-98f4-58e32cd89148}
    {35b1d3bb-2d4e-4a7c-9af0-f2f677af7c30}
    {375ff002-dd27-11d9-8f9c-0002b3988e81}
    {03E15B2E-CCA6-451C-8FB0-1E2EE37A27DD}
    {0886dae5-13ba-49d6-a6ef-d0922e502d96}
    {0A14D3FF-EC53-450F-AA30-FFBC55BE26A2}
    {15AD6165-BAA2-492B-B3CC-E7925D2FAB97}
    {27E23E49-0BAD-437C-9F4A-F1F8682535CA}
    {276D4FD3-C41D-465F-8CA9-A82A7762DF32}
    {35B1D3BB-2D4E-4A7C-9AF0-F2F677AF7C30}
    {375ff002-dd27-11d9-8f9c-0002b3988e81}
    {397A2E5F-348C-482D-B9A3-57D383B483CD}
    {45597c98-80f6-4549-84ff-752cf55e2d29}
    {45BA127D-10A8-46EA-8AB7-56EA9078943C}
    {4F8E67D6-DE03-480B-80AA-52F9C1AEFFEA}
    {515980c3-57fe-4c1e-a561-730dd256ab98}
    {53BEDF0B-4E5B-4183-8DC9-B844344FA104}
    {57360832-5F9B-4190-8467-000D2D510212}
    {5BBEE68B-389E-4B6A-813D-BEBDAB09E6EE}
    {682159d9-c321-47ca-b3f1-30e36b2ec8b9}
    {69F9CB25-25E2-4BE1-AB8F-07AA7CB535E8}
    {6A2A9381-5A92-4296-9397-564673AE1FDD}
    {6f33340d-8a01-473a-b75f-ded88c8360ce}
    {6f5bad87-9d5e-459f-bd03-3957407051ca}
    {75dff2b7-6936-4c06-a8bb-676a7b00b24b}
    {8E4062D9-FE1B-4B9E-AA16-5E8EEF68F48E}
    {94291A92-7486-487B-BC9A-206A12880F02}
    {A5B020FD-E04B-4E67-B65A-E7DEED25B2CF}
    {A7246883-0625-4321-94D2-A9B121E7E63A}
    {ADAB9B51-4CDD-4AF0-892C-AB7FA7B3293F}
    {BB07BACD-CD56-4E63-A8FF-CBF0355FB9F4}
    {BB2D41DF-7E34-4F06-8F51-007C9CAD36BE}
    {bdb57ff2-79b9-4205-9447-f5fe85f37312}
    {C88A4279-5ADC-4465-927F-6B19777AA5F9}
    {CCE1CB19-F9B3-4017-9541-DDA1B03F9A43}
    {cdc32574-7521-4124-90c3-8d5605a34933}
    {CECAD1B6-9620-4295-93C6-85B305D82AE4}
    {ceff45ee-c862-41de-aee2-a022c81eda92}
    {D0565000-9DF4-11D1-A281-00C04FCA0AA7}
    {DC0C2640-1415-4644-875C-6F4D769839BA}
    {E0BA3BF5-25EF-459F-9EE0-855FD3666692}
    {E1BA41AD-4A1D-418F-AABA-3D1196B423D3}
    {ECABB0C6-7F19-11D2-978E-0000F8757E2A}
    {ed1d0fdf-4414-470a-a56d-cfb68623fc58}
    {F01D6448-0959-4E38-B6F6-B6643D4558FE}
    {f7fa3149-91e7-43b7-8040-b707688ced1a}
    {F9A874B6-F8A8-4D73-B5A8-AB610816828B}
    {FBF23B40-E3F0-101B-8488-00AA003E56F8}
"@
    $Win2k12BlackList = @"
    00021401-0000-0000-C000-000000000046
    35b1d3bb-2d4e-4a7c-9af0-f2f677af7c30
    45BA127D-10A8-46EA-8AB7-56EA9078943C
    515980c3-57fe-4c1e-a561-730dd256ab98
    682159d9-c321-47ca-b3f1-30e36b2ec8b9
    75dff2b7-6936-4c06-a8bb-676a7b00b24b
    8A99553A-7971-4445-93B5-AAA43D1433C5
    9AA46009-3CE0-458A-A354-715610A075E6
    ceff45ee-c862-41de-aee2-a022c81eda92
"@
    $Win2k16BlackList = @"
    00021401-0000-0000-C000-000000000046
    35b1d3bb-2d4e-4a7c-9af0-f2f677af7c30
    397A2E5F-348C-482D-B9A3-57D383B483CD
    45597c98-80f6-4549-84ff-752cf55e2d29
    515980c3-57fe-4c1e-a561-730dd256ab98
    57360832-5F9B-4190-8467-000D2D510212
    682159d9-c321-47ca-b3f1-30e36b2ec8b9
    69F9CB25-25E2-4BE1-AB8F-07AA7CB535E8
    75dff2b7-6936-4c06-a8bb-676a7b00b24b
    8A99553A-7971-4445-93B5-AAA43D1433C5
    cdc32574-7521-4124-90c3-8d5605a34933
    CECAD1B6-9620-4295-93C6-85B305D82AE4
    ceff45ee-c862-41de-aee2-a022c81eda92
    E0BA3BF5-25EF-459F-9EE0-855FD3666692
    ed1d0fdf-4414-470a-a56d-cfb68623fc58
"@
    $CustomBlackListFile = "Custom_Blaclisted_CLSIDs_$ComputerName.txt"

    $VulnerableSubset = @"
    Shell
    Execute
    Navigate
    DDEInitiate
    CreateObject
    RegisterXLL
    ExecuteLine
    NewCurrentDatabase
    Service
    Create
    Run
    Exec
    Invoke
    File
    Method
    Explore
"@
    $PossibleVulnerableFile = "Possible_Vuln_DCOMapps_$ComputerName.txt"

    # Check the DCOM applications on the target system and write these to a textfile
    function Get-DCOMApplications {

        # Get DCOM applications
        Write-Host "`r[i] Retrieving DCOM applications." -ForegroundColor Yellow
        $DCOMApplications = Get-CimInstance Win32_DCOMApplication
        

        # Write the results to a text file
        Try {
            Out-File -FilePath "$ResultDir\$DCOMApplicationsFile" -InputObject $DCOMApplications -Encoding ascii -ErrorAction Stop
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }

        Write-Host "`r[+] DCOM applications retrieved and written to $ResultDir\$DCOMApplicationsFile." -ForegroundColor Green
        Return $DCOMApplications  
    }

    # Function that checks for the default permissions parameter in the registry and cross references this with the available DCOM Applications on the system
    function Get-DefaultPermissions {

        # Map the path to HKEY_CLASSES_ROOT
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null

        # Loop through the registry and check every key for the LaunchPermission property, we're only interested in the keys without this property
        Write-Host "[i] Checking DCOM applications with default launch permissions..." -ForegroundColor Yellow
        $DefaultPermissionsAppID = Get-ChildItem -Path HKCR:\AppID\ | ForEach-Object {
            if(-Not($_.Property -Match "LaunchPermission")) {
                $_.Name.Replace("HKEY_CLASSES_ROOT\AppID\","")
            }
        }



        # Store the DCOM applications present on the target machine in a variable
        $DCOMApplications = Get-DCOMApplications

        # Check which DCOM applications have the default permissions set
        $DefaultPermissions = $DCOMApplications | Select-String -Pattern $DefaultPermissionsAppID
        Write-Host "[+] Found $($DefaultPermissions.Count) DCOM applications without 'LaunchPermission' subkey!" -ForegroundColor Green

        # Write the results to the LaunchPermissionFile
        Try {
            Out-File -FilePath "$ResultDir\$LaunchPermissionFile" -InputObject $DefaultPermissions -Encoding ascii -ErrorAction Stop
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }

        Write-Host "[+] DCOM default LaunchPermission results written to $ResultDir\$LaunchPermissionFile" -ForegroundColor Green
        Return $DefaultPermissions
    }

    # Function to retrieve the CLSIDs for DCOM applications without LaunchPermissions set
    function Get-CLSID($DefaultLaunchPermission) {

        # Extract all the AppIDs from the list with the default LaunchPermissions
        $DCOMAppIDs = $DefaultLaunchPermission | Select-String -Pattern '\{(?i)[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}' | ForEach-Object {
                $_.Matches.Value
        }

        # Define variable to store the results
        $DCOMCLSIDs = @()

        # Map the path to HKEY_CLASSES_ROOT
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null

        Write-Host "[i] Retrieving CLSID's..." -ForegroundColor Yellow
        # Loop through the registry and check which AppID with default LaunchPermissions corresponds with which CLSID  
        (Get-ChildItem -Path HKCR:\CLSID\ ).Name.Replace("HKEY_CLASSES_ROOT\CLSID\","") | ForEach-Object {
            if ($DCOMAppIDs -eq (Get-ItemProperty -Path HKCR:\CLSID\$_).'AppID') {
                $DCOMCLSIDs += "Name: " + (Get-ItemProperty -Path HKCR:\CLSID\$_).'(default)' + " CLSID: $_"
            } 
        }

        # Write the output to a file
        Try {
            Out-File -FilePath "$ResultDir\$CLSIDFile" -InputObject $DCOMCLSIDs -Encoding ascii -ErrorAction Stop
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }
        Write-Host "`r[+] DCOM application CLSID's written to $ResultDir\$CLSIDFile" -ForegroundColor Green

        # Extract the DCOM CLSIDs for future usage
        $ExtractedCLSIDs = $DCOMCLSIDs | Select-String -Pattern '\{(?i)[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}' | ForEach-Object {
            $_.Matches.Value
        }
        
        # Return the extracted CLSIDs
        Return $ExtractedCLSIDs
    }

    # Function to loop over the DCOM CLSIDs and check which CLSIDs hold more than the default amount of MemberTypes
    function Get-MemberTypeCount($CLSIDs) {

        Write-Host "[i] Checking MemberType count..." -ForegroundColor Yellow

        # Check the default number of MemberType on the system, CLSID that is being used as a reference is the built in "Shortcut" CLSID
        # CLSID located at HKEY_CLASSES_ROOT\CLSID\{00021401-0000-0000-C000-000000000046}
        $DefaultMemberCount = Invoke-Command -ScriptBlock {
            # Check the default number of MemberType on the system, CLSID that is being used as a reference is the built in "Shortcut" CLSID
            # CLSID located at HKEY_CLASSES_ROOT\CLSID\{00021401-0000-0000-C000-000000000046}
            $DefaultMember = [activator]::CreateInstance([type]::GetTypeFromCLSID("00021401-0000-0000-C000-000000000046","localhost"))
            $DefaultMemberCount = ($DefaultMember | Get-Member).Count
            # Release the COM Object that was instantiated for getting the reference count of default MemberTypes
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($DefaultMember) | Out-Null

            Return $DefaultMemberCount
        }
        Write-Host "[i] Default MemberType count is: $DefaultMemberCount" -ForegroundColor Yellow

        # Create an array to store the potentially interesting DCOM applications
        $CLSIDCount = @()
        # Create an array to store the potentially vulnerable DCOM applications
        $VulnerableCLSID = @()
        # Create an array to store errors as a log
        $ErrorLog = @()

        # Read in the Blacklist based on the OS that was given as a parameter
        switch($OS) {
            "win7" {
                $DefaultBlackList = $Win7BlackList
                Break
            }
            "win10" {
                $DefaultBlackList = $Win10BlackList
            }
            "win2k12" {
                $DefaultBlackList = $Win2k12BlackList
            }
            "win2k16" {
                $DefaultBlackList = $Win2k16BlackList
            }
        }

        $CLSIDs | ForEach-Object {
            $CLSID = $_
            if (-not ($DefaultBlackList | ForEach-Object {$_ -Match $CLSID})) {
                $MemberCount = Invoke-Command -ScriptBlock {
                    Write-Host -NoNewline "`r[i] Checking CLSID: $CLSID" -ForegroundColor Yellow
                    Try {
                        $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID("$CLSID","localhost"))
                        $MemberCount = ($COM | Get-Member).Count
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($COM) | Out-Null -ErrorAction Continue
                        Return $MemberCount
                    } Catch [System.Runtime.InteropServices.COMException], [System.Runtime.InteropServices.InvalidComObjectException], [System.UnauthorizedAccessException], [System.InvalidOperationException] {

                    }
                }
                if (-not ($MemberCount -eq $DefaultMemberCount) -and ($MemberCount -gt 0)) {
                    $CLSIDCount += "CLSID: $CLSID MemberType Count: $MemberCount"
                    $VulnerableCLSID += $CLSID
                }
            }
        }
        #$VulnerableCLSID
    
        #Create-ErrorLog($ErrorLog)

        Try {
            Write-Host "[i] Writing CLSIDs without default MemberType count to $MemberTypeCountFile" -NoNewline -ForegroundColor Yellow
            "[+] The following COM objects might be interesting to look into: " | Out-File -FilePath .\$MemberTypeCountFile -Encoding ascii -ErrorAction Stop
            Out-File -FilePath "$ResultDir\$MemberTypeCountFile" -InputObject $CLSIDCount -Append -Encoding ascii -ErrorAction Stop
            Write-Host "`r[i] Written CLSIDs without default MemberType count to $ResultDir\$MemberTypeCountFile" -ForegroundColor Yellow
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }

        Write-Host "[i] Trying potentially vulnerable CLSIDs with $VulnerableSubsetFile" -ForegroundColor Yellow
        #Get-VulnerableDCOM($VulnerableCLSID)

        Return $CLSIDCount, $VulnerableCLSID
    }

    # Function to provide the option to create a custom Blacklist for future use on other machines in for example a Microsoft Windows Domain
    function Create-CustomBlackList($BlackListedCLSIDs) {

        Write-Host "[i] Custom Blacklist parameter was given, building Blacklist..." -ForegroundColor Yellow

        Try {
            Write-Host "[i] Writing $($BlacklistedCLSIDs.Count) CLSIDs to the custom Blacklist" -NoNewline -ForegroundColor Yellow
            Out-File -FilePath "$ResultDir\$CustomBlackListFile" -InputObject $BlackListedCLSIDs -Encoding ascii -ErrorAction Stop
            Write-Host "`r[+] Written $($BlacklistedCLSIDs.Count) CLSIDs to $BlackListedCLSIDs" -ForegroundColor Green
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }
        Write-Host "[+] Blacklisted DCOM application CLSID's written to $ResultDir\$CLSIDFile" -ForegroundColor Green
    }

    # Function to write errors or blacklisted occurences to an errorlog
    function Create-ErrorLog ($ErrorLog) {

        Try {
            Write-Host "`n[i] Writing $($ErrorLog.Count) errors to logfile" -NoNewline -ForegroundColor Yellow
            Out-File -FilePath "$ResultDir\errorlog_$ComputerName.txt" -InputObject $ErrorLog -Encoding ascii -ErrorAction Stop
            Write-Host "`r[i] Written $($ErrorLog.Count) errors to logfile" -ForegroundColor Yellow
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }
    }

    # Function that checks the possible vulnerable DCOM applications with the textfile of strings
    # NOTE: This checks with a max depth of 4
    function Get-VulnerableDCOM($VulnerableCLSIDs) {
        <# 
        !!! NOTE !!!
        The following variable assignment is very bad practice, however I could not figure out how to suppress the errors thrown
        The suppressed errors are not of importance for enumerating this script. The errors are generated by looping over the 
        DCOM MemberTypes, if there are no more MemberTypes but the depth is less than 3 it generates the error
        !!! NOTE !!! 
        #>
        $ErrorActionPreference = 'SilentlyContinue'

        # Create array to store potentially vulnerable CLSIDs
        $VulnerableCLSID = @()

        Write-Host "[i] This might take a while...`n" -ForegroundColor Yellow
        # Loop over the interesting CLSIDs from the function Get-MemberTypeCount
        $VulnerableCLSIDs | ForEach-Object {
            # Add a slight delay between each loop
            Start-Sleep -Milliseconds 200
            $CLSID = $_ 
            Write-Host -NoNewline "`r[i] Checking CLSID: $CLSID" -ForegroundColor Yellow
            $Vulnerable = Invoke-Command -ScriptBlock {
                # Instantiate the CLSID
                $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID, "localhost"))
                # Get all the MemberType names of the $COM instantiation for future use
                $COMMemberNames1 = $COM | Get-Member | ForEach-Object {$_.Name}
                # Create an array for members of depth 3
                $VulnCOM = @()
                Try {
                    # Loop over the members and their names (Depth 1)
                    $COM | Get-Member | ForEach-Object {
                        $MemberType = $_.Name
                        if ($VulnerableSubset | ForEach-Object {$_ -Match $MemberType}) {
                            $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $CLSID Path: " + '$COM' + "." + $_.Name
                        }
                    }
                    # Loop over the members and their names (Depth 2)
                    $COMMemberNames1 | ForEach-Object {
                        $NameDepth1 = $_
                        $COMDepth1 = $COM.$NameDepth1
                        if ((Get-Member -InputObject $COMDepth1).Count -ne 12) {
                            Get-Member -InputObject $COMDepth1 | ForEach-Object {
                                $MemberType = $_.Name
                                # Check if the membernames are present in the subset with strings that might indicate a vulnerability
                                if ($VulnerableSubset | ForEach-Object {$_ -Match $MemberType}) {
                                    $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $CLSID Path: " + '$COM' + "." + $NameDepth1 + "." + $_.Name
                                }
                            }
                        }
                        # Loop over the members and their names (Depth 3)
                        $COMDepth1 | ForEach-Object {
                            $COMDepth2 = $_
                            if ((Get-Member -InputObject $COMDepth2).Count -ne 12) {
                                Get-Member -InputObject $COMDepth2 | ForEach-Object {
                                    $MemberType = $_.Name
                                    # Check if the membernames are present in the subset with strings that might indicate a vulnerability
                                    if ($VulnerableSubset | ForEach-Object {$_ -Match $MemberType}) {
                                        $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $CLSID Path: " + '$COM' + "." + $NameDepth1 + "." + $_.Name
                                    }
                                }
                            }
                            # Loop over the members and their names (Depth 4)
                            Get-Member -InputObject $COMDepth2 | ForEach-Object {$_.Name} | ForEach-Object {
                                $COMDepth3 = $_
                                $NameDepth2 = $COMDepth2.$COMDepth3
                                if ((Get-Member -InputObject $NameDepth2).Count -ne 12) {
                                    Get-Member -InputObject $NameDepth2 | ForEach-Object {
                                        $MemberType = $_.Name
                                        # Check if the membernames are present in the subset with strings that might indicate a vulnerability
                                        if ($VulnerableSubset | ForEach-Object {$_ -Match $MemberType}) {
                                            $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $CLSID Path: " + '$COM' + "." + $NameDepth1 + "." + $COMDepth3 + "." + $_.Name
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Return $VulnCOM
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($COM) | Out-Null -ErrorAction Continue
                } Catch [System.InvalidOperationException], [Microsoft.PowerShell.Commands.GetMemberCommand] {
                    Write-Host "[i] Caught exception"
                }
            }
            $VulnerableCLSID += $Vulnerable
        }
        # Store the potentially vulnerable MemberTypes and CLSIDs, remove duplicates
        #$OutputVulnerableCLSID = $VulnerableCLSID | Sort-Object -Unique

        # Write the possible Vulnerable DCOM applications to file
        Try {
            Write-Host "`n[i] Writing possible vulnerable DCOM applications to: $PossibleVulnerableFile" -NoNewline -ForegroundColor Yellow
            "Instantiated with the following command: " + '$COM' + ' = [activator]::CreateInstance([type]::GetTypeFromCLSID("{CLSID}", "localhost"))' + "`n`n" | Out-File .\$PossibleVulnerableFile 
            Out-File -FilePath "$ResultDir\$PossibleVulnerableFile" -InputObject $VulnerableCLSID -Append -ErrorAction Stop
            Write-Host "`r[i] Written possible vulnerable DCOM applications to: $ResultDir\$PossibleVulnerableFile" -ForegroundColor Yellow
        } Catch [System.IO.IOException] {
            Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
            Write-Host "[!] Exiting..."
            Break
        }

        Return $VulnerableCLSID
    }

    # Function to generate the HTML report with the results
    function HTMLReport {

        $ReportData = @()

        # Standard regex to extract CLSID/AppID
        $CLSIDPattern = '\{(?i)[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}'
        <#
        $ImagePath = ".\logo_hackdefense.png"
        $ImageBits =  [Convert]::ToBase64String((Get-Content $ImagePath -Encoding Byte))
        $ImageFile = Get-Item $ImagePath
        $ImageType = $ImageFile.Extension.Substring(1) #strip off the leading .
        $ImageTag = "<Img src='data:image/$ImageType;base64,$($ImageBits)' Alt='$($ImageFile.Name)' style='float:left' width='120' height='120' hspace=10><br><br><br><br>"

        $ReportData += $ImageTag
        $ReportData += "<br><br>"
        #>

        $ReportData += "<H2>OS Info</H2>"

        $ReportData += Get-Ciminstance -ClassName win32_operatingsystem | Select-Object @{
            Name="Operating System";Expression= {$_.Caption}
        },Version,InstallDate | ConvertTo-Html -Fragment -As List

        # Create a table for the DCOM objects that are likely to be vulnerable
        $COMName = '[a-z]*\s[A-Z][a-zA-Z0-9]*\s\(.*\)|[a-z]*\s[A-Z][a-zA-Z0-9]*\(.*\)'
        $COMPath = '(?i)\$COM\.\S*'
        $VulnInfo = $VulnerableCLSID | ForEach-Object {
            ($_ | Select-String -Pattern $CLSIDPattern | ForEach-Object {"<tr><td>$($_.Matches.Value)</td>"})
            ($_ | Select-String -Pattern $COMName | ForEach-Object {"<td>$($_.Matches.Value)</td>"})
            ($_ | Select-STring -Pattern $COMPath | ForEach-Object {"<td>$($_.Matches.value)</td></tr>"})
        }
        $ReportData += "<H2>Possible Vulnerable DCOM</H2>"
        $ReportData += "<br><table><colgroup><col /><col /><col /></colgroup><tr><th>CLSID</th><th>MemberType Name</th><th>Path</th>" + $VulnInfo + "</table>"

        # Write the CLSIDs with MemberType counts that differ from the default
        $CountPattern = '[0-9]{1,2}$'
        $MembersCount = $MemberTypeCount | ForEach-Object {
            ($_ | Select-String -Pattern $CLSIDPattern | ForEach-Object {"<tr><td>$($_.Matches.Value)</td>"})
            ($_ | Select-STring -Pattern $CountPattern | ForEach-Object {"<td>$($_.Matches.value)</td></tr>"})
        }
        $ReportData += "<H2>Interesting CLSIDs</H2>"
        $ReportData += "<br><table><colgroup><col /><col /><col /></colgroup><tr><th>CLSID</th><th>MemberType Count</th>" + $MembersCount + "</table>"

        # Create a table with the contents of DCOM applications that have no LaunchPermissions set
        $DefaultPermissions = Get-Content "$ResultDir\$LaunchPermissionFile"
        $NamePattern = '[^(Win32_DCOMApplication:)](.*?)\('
        $DefaultDCOM = $DefaultPermissions | ForEach-Object {
            Try {
                ($_ | Select-String -Pattern $NamePattern | ForEach-Object {"<tr><td>$($_.Matches.Value)</td>"}).Replace("(","")
                ($_ | Select-String -Pattern $CLSIDPattern | ForEach-Object {"<td>$($_.Matches.value)</td></tr>"})
            } Catch {
                # Non-terminating error
            }
        }
        $ReportData += "<H2>DCOM Applications with Default Permissions</H2>"
        $ReportData += "<br><table><colgroup><col /><col /><col /></colgroup><tr><th>Name</th><th>AppID</th>" + $DefaultDCOM + "</table>"

        # Create a table with the contents of the DCOM applications
        $ReportData += "<H2>DCOM Applications on $ComputerName</H2>"
        $dcom = $DCOMApplications | Select-Object Name,Description,AppID
        [xml]$html = $dcom | ConvertTo-Html -Fragment
        # Keep adding new rows and columns as long as there are entries in the list of DCOM applications
        for ($i=1;$i -le $html.table.tr.count-1;$i++) {
            if ($html.table.tr[$i].td[3] -eq 0) {
            $class = $html.CreateAttribute("class")
            # Color the string red if no other entries are found
            $class.value = 'alert'
            $html.table.tr[$i].attributes.append($class) | out-null
            }
        }
        # Add the table to the HTML document
        $ReportData += $html.InnerXML

        # Footer containing the date of when the report was generated
        $ReportData += "<p class='footer'>Date of reporting: $($CurrentDate)</p>"

        # Create a style for the HTML page
        $convertParams = @{ 
            head = @"
                <Title>DCOMrade Report - $($ComputerName)</Title>
                <style>
                body { background-color:#E5E4E2;
                    font-family:Monospace;
                    font-size:10pt; 
                }
                td, th { border:0px solid black; 
                    border-collapse:collapse;
                    white-space:pre; 
                }
                th { color:white;
                background-color:black; 
                }
                table, tr, td, th { 
                    padding: 2px; margin: 0px ;white-space:pre; 
                }
                tr:nth-child(odd) {
                    background-color: lightgray
                }
                table { 
                    width:95%;margin-left:5px; margin-bottom:20px;
                }
                h2 {
                    font-family:Tahoma;
                    color:#6D7B8D;
                }
                .alert {
                    color: red; 
                }
                .footer { 
                    color:green; 
                    margin-left:10px; 
                    font-family:Tahoma;
                    font-size:8pt;
                    font-style:italic;
                }
                </style>
"@
            body = $ReportData
        }
        ConvertTo-Html @convertParams | Out-File "$ResultDir\DCOMrade-Report-$ComputerName.html"
    }

    if (!(Test-Path $ResultDir)) {
        New-Item -ItemType Directory -Force -Path $ResultDir
    }

    $DCOMApplications = Get-DCOMApplications
    # Get DCOM applications with default LaunchPermissions set
    $DCOMDefaultLaunchPermissions = Get-DefaultPermissions
    # Get the CLSIDs of the DCOM applications with default LaunchPermissions
    $DCOMApplicationsCLSID = Get-CLSID($DCOMDefaultLaunchPermissions)
    # Test the amount of members by instantiating these as DCOM, returns count and possible vulnerable DCOM objects
    $MemberTypeCount, $PossibleVulnerableCLSID = Get-MemberTypeCount($DCOMApplicationsCLSID)
    # Get the potentially vulnerable DCOM objects and their paths
    $VulnerableCLSID = Get-VulnerableDCOM($PossibleVulnerableCLSID)
    # Generate the HTML report
    HTMLReport
}
