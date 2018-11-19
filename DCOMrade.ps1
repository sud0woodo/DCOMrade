<#
.SYNOPSIS
Powershell script for checking possibly vulnerable DCOM applications.

.DESCRIPTION
This script is able to enumerate the DCOM applications and check the Methods / Properties of the DCOM applications for possible vulnerabilities. 

The script will enumerate the DCOM applications present on the machine and verify which CLSID belongs to which DCOM application.

The DCOM applications will get instantiated by the script and the amount of MemberTypes present will be checked, the DCOM applications might be interesting 
if it doesn't hold the same as the default amount of MemberTypes (this is checked by counting the amount of MemberTypes when instantiating the default CLSID 
of "Shortcut") and holds more MemberTypes than 0.

.PARAMETER ComputerName
The ComputerName of the victim machine

.PARAMETER User
The Username of the victim

.PARAMETER OS
The operating system of the target machine

.PARAMETER Domain
The name of the Microsoft Windows domain

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
https://github.com/sud0woodo/DCOMrade

.NOTES 
DISCLAIMER: I am not a developer, this code is probably not as efficient as it could have been. 
I am not responsible for the usage and outcomes of this tool, this tool was created for educational purposes.

Access to the local/Domain administrator account on the target machine is needed to enable PSRemoting and check/change the Firewall rules.
To enable the features needed, execute the following commands:

PS > Enable-PSRemoting -SkipNetworkProfileCheck -Force

Author: Axel Boesenach / sud0woodo
#>

# Assign arguments to parameters
param(
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
$Win7BlackListFile = "Win7BlacklistedCLSIDS.txt"
$Win10BlackListFile = "Win10BlackListedCLSIDS.txt"
$Win2k12BlackListFile = "Win2k12BlackListedCLSIDs.txt"
$Win2k16BlackListFile = "Win2k16BlackListedCLSIDs.txt"
$CustomBlackListFile = "Custom_Blaclisted_CLSIDs_$ComputerName.txt"

$VulnerableSubsetFile = "VulnerableSubset.txt"
$PossibleVulnerableFile = "Possible_Vuln_DCOMapps_$ComputerName.txt"

# Welcome logo
Write-Host "MMMMMMMMMMMMMMMMMMMMMWN" -f Yellow -nonewline; Write-Host "0O" -f Red -nonewline; Write-Host "KWMMMMMMMMMMMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMMMMMMMMMMMMMMMMMN" -f Yellow -nonewline; Write-Host "OooO" -f Red -nonewline; Write-Host "XWMMMMMMMMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMMMMMMMMMMMMMMMMMMWK" -f Yellow -nonewline; Write-Host "o;cx" -f red -nonewline; Write-Host "KWMMMMMMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMMMMN0kxkOO0KXNWMMMMNk" -f Yellow -nonewline; Write-Host ":,:x" -f red -nonewline; Write-Host "KWMMMMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMMN0o" -f Yellow -nonewline; Write-Host ";'''',;" -f Red -nonewline; Write-Host "lOXNMMMMMW0" -f Yellow -nonewline; Write-Host "c,,:" -f Red -nonewline; Write-Host "kNMMMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMNOl" -f Yellow -NoNewline; Write-Host ";'''''," -f Red -nonewline; Write-Host "ckXWMMMMMMMMWKl" -f Yellow -nonewline; Write-Host ",',o" -f Red -nonewline; Write-Host "KWMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMWNOl;" -f Yellow -NoNewline; Write-Host "'''''''" -f Red -nonewline; Write-Host "c0WMMMMMMMMMMMWKc" -f Yellow -nonewline; Write-Host "''," -f Red -nonewline; Write-Host "lKWMM" -f Yellow -NoNewline; Write-Host " ###DCOMrade###DCOMrade###DCOMrade###DCOMrade###DCOMrade###DCOMrade###### " -f Red
Write-Host "MMW0l" -f Yellow -NoNewline; Write-Host ",'''''',''," -f Red -nonewline; Write-Host "ckXWMMMMMMMMMMWO" -f Yellow -nonewline; Write-Host ":'',o" -f Red -nonewline; Write-Host "XMM" -f Yellow -NoNewline; Write-Host " ######DCOMRADE###DCOMRADE###DCOMRADE###DCOMRADE###DCOMRADE###DCOMRADE### " -f Red
Write-Host "MMMXkccx" -f Yellow -NoNewline; Write-Host ",'k',l,''," -f Red -nonewline; Write-Host "ck0XWMMMMMMMMNd" -f Yellow -nonewline; Write-Host ",'';" -f Red -nonewline; Write-Host "xWM" -f Yellow -NoNewline; Write-Host " ##########DCOMrade###DCOMrade###DCOMrade###DCOMrade###DCOMrade###DCOM### " -f Red
Write-Host "MMMMWXkcckXWMNO" -f Yellow -NoNewline; Write-Host "l,'',;" -f Red -nonewline; Write-Host "ckXWMMMMMMWk" -f Yellow -nonewline; Write-Host ";'''" -f Red -nonewline; Write-Host "lXM" -f Yellow -NoNewline; Write-Host " ###" -f Red -NoNewline; Write-Host "   Powershell Script to enumerate vulnerable DCOM Applications" -f Yellow -NoNewline; Write-Host "    ### " -f Red
Write-Host "MMMMMMWNNWMMMMWNO" -f Yellow -NoNewline; Write-Host "l,'''," -f Red -nonewline; Write-Host "cxXWMMMMWO" -f Yellow -nonewline; Write-Host ";'''" -f Red -nonewline; Write-Host "lKM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMMMMMMMMMMMNO" -f Yellow -NoNewline; Write-Host ",;,''," -f Red -nonewline; Write-Host "cxXWMMNd" -f Yellow -nonewline; Write-Host ",'''" -f Red -nonewline; Write-Host "oXM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMMMMMMMMMMMMMNKO" -f Yellow -NoNewline; Write-Host "l,''," -f Red -nonewline; Write-Host "cxXNk" -f Yellow -nonewline; Write-Host ":''';" -f Red -nonewline; Write-Host "kWM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMMMWWX0OkOXWMMMMMMNk" -f Yellow -NoNewline; Write-Host ",'',:c" -f Red -nonewline; Write-Host "" -f Yellow -nonewline; Write-Host ";'''; " -f Red -nonewline; Write-Host "xNMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMMMWNOl" -f Yellow -NoNewline; Write-Host ":,,'," -f Red -nonewline; Write-Host "cdk0KXNNNX" -f Yellow -nonewline; Write-Host "0o;''''''':" -f Red -nonewline; Write-Host "kNMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MMMWKkl" -f Yellow -NoNewline; Write-Host ";'';ll;''',;::cc::;,''''''," -f Red -nonewline; Write-Host "lKWMMM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "MNOo" -f Yellow -NoNewline; Write-Host ":,'," -f Red -nonewline; Write-Host "cxKNN0xl" -f Yellow -NoNewline; Write-Host ";,''''''''''," -f Red -nonewline; Write-Host "::" -f Yellow -NoNewline; Write-Host ",''," -f Red -nonewline; Write-Host ":xKWM" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "Ko" -f Yellow -NoNewline; Write-Host ",'''," -f Red -nonewline; Write-Host "oKWMMMMMNKOkdddooodxk0XKkc" -f Yellow -NoNewline; Write-Host ",''," -f Red -nonewline; Write-Host ":xX" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "d" -f Yellow -NoNewline; Write-Host ",''," -f Red -nonewline; Write-Host ":xXMMMMMMMMMMMMMMWWMMMMMMMWXkc" -f Yellow -NoNewline; Write-Host ",''" -f Red -nonewline; Write-Host ";x" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red
Write-Host "Oc,;" -f Yellow -NoNewline; Write-Host "o0WMMMMMMMMMMMMMMMMMMMMMMMMMMWKo" -f Yellow -NoNewline; Write-Host ",," -f Red -nonewline; Write-Host "c0" -f Yellow -NoNewline; Write-Host " ######################################################################## " -f Red

# Add victim machine to trusted hosts
# NOTE: This will prompt if you are sure you want to add the remote machine to the trusted hosts, press Y to confirm
$TrustedClients = Get-Item WSMan:\localhost\Client\TrustedHosts
if ($ComputerName -notin $TrustedClients) {
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$ComputerName" -Concatenate
}

# Create a new non-interactive Remote Powershell Session
function Get-Session {
    # When connecting to a Domain, the User should be prepended with the Domain name
    if ($Domain) {
        Try {
            Write-Host "[i] Connecting to $ComputerName" -ForegroundColor Yellow
            $session = New-PSSession -ComputerName $ComputerName -Credential $Domain\$User -ErrorAction Stop
            Write-Host "[+] Connected to $ComputerName" -ForegroundColor Green
            return $session
        } Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Host "[!] Creation of Remote Session failed, Access is denied." -ForegroundColor Red
            Write-Host "[!] Exiting..." -ForegroundColor Red
            Break
        } 
    } else {
        Try {
            Write-Host "[i] Connecting to $ComputerName" -ForegroundColor Yellow
            $session = New-PSSession -ComputerName $ComputerName -Credential $ComputerName\$User -ErrorAction Stop
            Write-Host "[+] Connected to $ComputerName" -ForegroundColor Green
            return $session
        } Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Host "[!] Creation of Remote Session failed, Access is denied." -ForegroundColor Red
            Write-Host "[!] Exiting..." -ForegroundColor Red
            Break
        }
    }
}

# Check the DCOM applications on the target system and write these to a textfile
function Get-DCOMApplications {

    # Get DCOM applications
    Write-Host "`r[i] Retrieving DCOM applications." -ForegroundColor Yellow
    $DCOMApplications = Invoke-Command -Session $remotesession -ScriptBlock {
        Get-CimInstance Win32_DCOMapplication
    }

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
    Invoke-Command -Session $remotesession -ScriptBlock {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    } | Out-Null

    # Loop through the registry and check every key for the LaunchPermission property, we're only interested in the keys without this property
    Write-Host "[i] Checking DCOM applications with default launch permissions..." -ForegroundColor Yellow
    Invoke-Command -Session $remotesession -ScriptBlock {
        Get-ChildItem -Path HKCR:\AppID\ | ForEach-Object {
            if(-Not($_.Property -Match "LaunchPermission")) {
                $_.Name.Replace("HKEY_CLASSES_ROOT\AppID\","")
            }
        } 
    } -OutVariable DefaultPermissionsAppID | Out-Null 


    # Store the DCOM applications present on the target machine in a variable
    $DCOMApplications = Get-DCOMApplications($remotesession)

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

    Write-Host "[i] Retrieving CLSID's..." -ForegroundColor Yellow
    $RemoteDCOMCLSIDs = Invoke-Command -Session $remotesession -ScriptBlock {
        # Define variable to store the results
        $DCOMCLSIDs = @()
        # Loop through the registry and check which AppID with default LaunchPermissions corresponds with which CLSID
        (Get-ChildItem -Path HKCR:\CLSID\ ).Name.Replace("HKEY_CLASSES_ROOT\CLSID\","") | ForEach-Object {
            if ($Using:DCOMAppIDs -eq (Get-ItemProperty -Path HKCR:\CLSID\$_).'AppID') {
                $DCOMCLSIDs += "Name: " + (Get-ItemProperty -Path HKCR:\CLSID\$_).'(default)' + " CLSID: $_"
            } 
        }

        # Return the DCOM CLSIDs so these can be used locally
        Return $DCOMCLSIDs
    }

    # Write the output to a file
    Try {
        Out-File -FilePath "$ResultDir\$CLSIDFile" -InputObject $RemoteDCOMCLSIDs -Encoding ascii -ErrorAction Stop
    } Catch [System.IO.IOException] {
        Write-Host "[!] Failed to write output to file!" -ForegroundColor Red
        Write-Host "[!] Exiting..."
        Break
    }
    Write-Host "`r[+] DCOM application CLSID's written to $ResultDir\$CLSIDFile" -ForegroundColor Green

    # Extract the DCOM CLSIDs for future usage
    $ExtractedCLSIDs = $RemoteDCOMCLSIDs | Select-String -Pattern '\{(?i)[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}' | ForEach-Object {
        $_.Matches.Value
    }
    
    # Return the extracted CLSIDs
    Return $ExtractedCLSIDs
}

# Function to loop over the DCOM CLSIDs and check which CLSIDs hold more than the default amount of MemberTypes
function Get-MemberTypeCount($CLSIDs) {

    # Check the default number of MemberType on the system, CLSID that is being used as a reference is the built in "Shortcut" CLSID
    # CLSID located at HKEY_CLASSES_ROOT\CLSID\{00021401-0000-0000-C000-000000000046}
    $DefaultMemberCount = Invoke-Command -Session $remotesession -ScriptBlock {
        # Check the default number of MemberType on the system, CLSID that is being used as a reference is the built in "Shortcut" CLSID
        # CLSID located at HKEY_CLASSES_ROOT\CLSID\{00021401-0000-0000-C000-000000000046}
        $DefaultMember = [activator]::CreateInstance([type]::GetTypeFromCLSID("00021401-0000-0000-C000-000000000046","localhost"))
        $DefaultMemberCount = ($DefaultMember | Get-Member).Count
        # Release the COM Object that was instantiated for getting the reference count of default MemberTypes
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($DefaultMember) | Out-Null

        Return $DefaultMemberCount
    }

    # Create an array to store the potentially interesting DCOM applications
    $CLSIDCount = @()
    # Create an array to store the potentially vulnerable DCOM applications
    $VulnerableCLSID = @()

    # Read in the Blacklist based on the OS that was given as a parameter
    switch($OS) {
        "win7" {
            $DefaultBlackList = Get-Content -Path $Win7BlackListFile
            Break
        }
        "win10" {
            $DefaultBlackList = Get-Content -Path $Win10BlackListFile
        }
        "win2k12" {
            $DefaultBlackList = Get-Content -Path $Win2k12BlackListFile
        }
        "win2k16" {
            $DefaultBlackList = Get-Content -Path $Win2k16BlackListFile
        }
    }
    
    # Execute the following if block if the Blacklist parameter is set
    if ($Blacklist) {
        # Create an array to use as a future Blacklist of known non-vulnerable / interesting DCOM applications
        $CustomBlackList = @()
        # Loop over the list with CLSIDs to be tested
        $CLSIDs | ForEach-Object {
            # Add a little bit of delay to reduce the load
            Start-Sleep -Milliseconds 300
            Try {
                $CLSID = $_
                # Check if the CLSID is on the Blacklist
                if (-not ($CLSID | Select-String -Pattern $DefaultBlackList)) {
                    # Get the count of MemberType from the victim machine by instantiating it remotely 
                    $MemberCount = Invoke-Command -Session $remotesession -ScriptBlock {
                        Try {
                            # Instantiate the COM object by providing the CLSID and ComputerName and count the number of MemberTypes
                            Write-Host -NoNewline "`r[i] Checking CLSID: $Using:CLSID" -ForegroundColor Yellow
                            $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID("$Using:CLSID","localhost"))
                            $MemberCount = ($COM | Get-Member).Count
                            # Release the instantiated COM object
                            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($COM) | Out-Null -ErrorAction Continue
                            Return $MemberCount
                        } Catch [System.Runtime.InteropServices.COMException], [System.Runtime.InteropServices.InvalidComObjectException], [System.UnauthorizedAccessException], [System.InvalidOperationException] {
                            $ErrorLog += "[!] Caught Exception CLSID: $Using:CLSID"
                        }
                    } 
                    # Add the result to $CLSIDCount if it's more than 0 and not equal to the default amount of MemberTypes
                    if (-not ($MemberCount -eq $DefaultMemberCount) -and ($MemberCount -gt 0)) {
                        $CLSIDCount += "CLSID: $CLSID MemberType Count: $MemberCount"
                        # Add the potentially vulnerable CLSIDs to the array
                        $VulnerableCLSID += $CLSID
                        
                    } else {
                        # Add the CLSIDs to be blacklisted
                        $CustomBlackList += $CLSID
                    }
                } else {
                    #Write-Host "[i] Blacklisted CLSID found, skipping..." -ForegroundColor Yellow
                    $CustomBlackList += $CLSID
                }
            } Catch [System.UnauthorizedAccessException]{
                $ErrorLog += "[!] CLSID: $CLSID Cannot be instantiated"
                $CustomBlackList += $CLSID
            }
        }
        
        # Call the function to write the blacklisted CLSIDs to
        BlackList($CustomBlackList)
    
    } else {
        $CLSIDs | ForEach-Object {
            # Add a little bit of delay to reduce the load
            Start-Sleep -Milliseconds 200
            Try {
                $CLSID = $_
                # Check if the CLSID is on the Blacklist
                if (-not ($CLSID | Select-String -Pattern $DefaultBlackList)) {
                    $MemberCount = Invoke-Command -Session $remotesession -ScriptBlock {
                        Try {
                        # Instantiate the COM object by providing the CLSID and ComputerName and count the number of MemberTypes
                        Write-Host -NoNewline "`r[i] Checking CLSID: $Using:CLSID" -ForegroundColor Yellow
                        $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID("$Using:CLSID","localhost"))
                        $MemberCount = ($COM | Get-Member).Count
                        # Release the instantiated COM object
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($COM) | Out-Null -ErrorAction Continue
                        Return $MemberCount
                        } Catch [System.Runtime.InteropServices.COMException], [System.Runtime.InteropServices.InvalidComObjectException], [System.UnauthorizedAccessException], [System.InvalidOperationException] {
                            $ErrorLog += "[!] Caught Exception CLSID: $Using:CLSID"
                        }
                    }
                    # Add the result to $CLSIDCount if it's more than 0 and not equal to the default amount of MemberTypes
                    if (-not ($MemberCount -eq $DefaultMemberCount) -and ($MemberCount -gt 0)) {
                        $CLSIDCount += "CLSID: $CLSID MemberType Count: $MemberCount" 
                        # Add the potentially vulnerable CLSIDs to the array
                        $VulnerableCLSID += $CLSID
                    }
                } else {
                    $ErrorLog += "[i] Blacklisted CLSID found: $CLSID"
                }
                                
            } Catch {
                $ErrorLog += "[!] CLSID: $CLSID Cannot be instantiated"
            }
        }
    }

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

    Return $CLSIDCount, $VulnerableCLSID
}

# Function to provide the option to create a custom Blacklist for future use on other machines in for example a Microsoft Windows Domain
function BlackList($BlackListedCLSIDs) {

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

    # Read in the subset file with strings that might indicate a vulnerability
    $VulnerableSubset = Get-Content $VulnerableSubsetFile

    # Create array to store potentially vulnerable CLSIDs
    $VulnerableCLSID = @()

    Write-Host "[i] This might take a while...`n" -ForegroundColor Yellow
    # Loop over the interesting CLSIDs from the function Get-MemberTypeCount
    $VulnerableCLSIDs | ForEach-Object {
        # Add a slight delay between each loop
        Start-Sleep -Milliseconds 200
        $CLSID = $_ 
        Write-Host -NoNewline "`r[i] Checking CLSID: $CLSID" -ForegroundColor Yellow
        $Vulnerable = Invoke-Command -Session $remotesession -ScriptBlock {
            # Instantiate the CLSID
            $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID($Using:CLSID, "localhost"))
            # Get all the MemberType names of the $COM instantiation for future use
            $COMMemberNames1 = $COM | Get-Member | ForEach-Object {$_.Name}
            # Create an array for members of depth 3
            $VulnCOM = @()
            Try {
                # Loop over the members and their names (Depth 1)
                $COM | Get-Member | ForEach-Object {
                    if ($_.Name | Select-String -Pattern $Using:VulnerableSubset) {
                        $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $Using:CLSID Path: " + '$COM' + "." + $_.Name
                    }
                }
                # Loop over the members and their names (Depth 2)
                $COMMemberNames1 | ForEach-Object {
                    $NameDepth1 = $_
                    $COMDepth1 = $COM.$NameDepth1
                    if ((Get-Member -InputObject $COMDepth1).Count -ne 12) {
                        Get-Member -InputObject $COMDepth1 | ForEach-Object {
                            # Check if the membernames are present in the subset with strings that might indicate a vulnerability
                            if ($_.Name | Select-String -Pattern $Using:VulnerableSubset) {
                                $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $Using:CLSID Path: " + '$COM' + "." + $NameDepth1 + "." + $_.Name
                            }
                        }
                    }
                    # Loop over the members and their names (Depth 3)
                    $COMDepth1 | ForEach-Object {
                        $COMDepth2 = $_
                        if ((Get-Member -InputObject $COMDepth2).Count -ne 12) {
                            Get-Member -InputObject $COMDepth2 | ForEach-Object {
                                # Check if the membernames are present in the subset with strings that might indicate a vulnerability
                                if ($_.Name | Select-String -Pattern $Using:VulnerableSubset) {
                                    $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $Using:CLSID Path: " + '$COM' + "." + $NameDepth1 + "." + $_.Name
                                }
                            }
                        }
                        # Loop over the members and their names (Depth 4)
                        Get-Member -InputObject $COMDepth2 | ForEach-Object {$_.Name} | ForEach-Object {
                            $COMDepth3 = $_
                            $NameDepth2 = $COMDepth2.$COMDepth3
                            if ((Get-Member -InputObject $NameDepth2).Count -ne 12) {
                                Get-Member -InputObject $NameDepth2 | ForEach-Object {
                                    # Check if the membernames are present in the subset with strings that might indicate a vulnerability
                                    if ($_.Name | Select-String -Pattern $Using:VulnerableSubset) {
                                        $VulnCOM += "[+] Possible Vulnerability found: $_ CLSID: $Using:CLSID Path: " + '$COM' + "." + $NameDepth1 + "." + $COMDepth3 + "." + $_.Name
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

    # You can add a company logo here if you would like to have one in the HTML report
    <#
    $ImagePath = "[location of the logo]"
    $ImageBits =  [Convert]::ToBase64String((Get-Content $ImagePath -Encoding Byte))
    $ImageFile = Get-Item $ImagePath
    $ImageType = $ImageFile.Extension.Substring(1) #strip off the leading .
    $ImageTag = "<Img src='data:image/$ImageType;base64,$($ImageBits)' Alt='$($ImageFile.Name)' style='float:left' width='120' height='120' hspace=10><br><br><br><br>"

    $ReportData += $ImageTag
    #>

    $ReportData += "<br><br>"
    $ReportData += "<H2>OS Info</H2>"

    $ReportData += Invoke-Command -Session $remotesession -ScriptBlock {
        Get-Ciminstance -ClassName win32_operatingsystem | Select-Object @{Name="Operating System";Expression= {$_.Caption}},Version,InstallDate | 
        ConvertTo-Html -Fragment -As List
    }

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

# Start the remote session
$remotesession = Get-Session

# OPTIONAL and just to showcase really
# Test for the RPC Firewall rule, comment out the section above to enable this
#Get-RPCRule

# Get a list of all the DCOM applications on the target system
$DCOMApplications = Get-DCOMApplications

# Get DCOM applications with default LaunchPermissions set
$DCOMDefaultLaunchPermissions = Get-DefaultPermissions

# Get the CLSIDs of the DCOM applications with default LaunchPermissions
$DCOMApplicationsCLSID = Get-CLSID($DCOMDefaultLaunchPermissions)

# Test the amount of members by instantiating these as DCOM, returns count and possible vulnerable DCOM objects
Write-Host "[i] Checking MemberType count..." -ForegroundColor Yellow
$MemberTypeCount, $PossibleVulnerableCLSID = Get-MemberTypeCount($DCOMApplicationsCLSID)

# Get the potentially vulnerable DCOM objects and their paths
Write-Host "[i] Trying potentially vulnerable CLSIDs with $VulnerableSubsetFile" -ForegroundColor Yellow
$VulnerableCLSID = Get-VulnerableDCOM($PossibleVulnerableCLSID)

# Generate the HTML report
HTMLReport