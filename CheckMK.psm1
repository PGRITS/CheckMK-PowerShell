<#
.SYNOPSIS
	Funktionssammlung für CheckMK

.DESCRIPTION
    Dieses Modul soll mit der Zeit wachsen. Es sollen nicht unbedingt alle Funktionen der
    CheckMK API abgebildet werden, allerdings die am häufigsten verwendeten.
    Wenn jemand einen Schnittstelle der API anspricht, welche das Modul noch nicht abdeckt,
    kann er das Modul gerne ergänzen.

    -Verbose hilft Fehler zu finden. HTTP Error Codes lassen sich so anzeigen.
    In der Dokumentation zur API ist je Endpunkt aufgelistet, was welcher Code bedeutet.
    Lassen sich Fehler nicht erklären, kann die interaktive Dokumentation genutzt werden. Diese enthält
    bei falscher Syntax recht genaue Fehlerbeschreibungen.

.LINK
    Dokumentation
    https://<CheckMK-Host>/<sitename>/check_mk/openapi/
.LINK
    Interaktive Dokumentation
    https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/

#>
#region Connection

# Beispiel für Nutzung:
<#
# Verbindung aufbauen
$securePassword = Read-Host "CheckMK Passwort" -AsSecureString
$connection = Connect-CMK -Hostname "checkmk.example.com" -Sitename "prod" -Username "automation" -Secret $securePassword -TestConnection

# Verwenden
$hosts = Get-CMKHost -Connection $connection
$serverInfo = Get-CMKServerInfo -Connection $connection

# Später wiederverwenden (ohne erneute Passwort-Eingabe)
$connection = Connect-CMK -Hostname "checkmk.example.com" -Sitename "prod"

# Verbindung beenden
Disconnect-CMK -Connection $connection
#>

# Sichere Connection-Klasse

$ExistingTypes = [AppDomain]::CurrentDomain.GetAssemblies() | 
    ForEach-Object { 
        $assembly = $_
        $_.GetTypes() | Where-Object { $_.Name -eq 'CMKConnection' } |
        ForEach-Object { [PSCustomObject]@{ Type = $_; Assembly = $assembly.FullName } }
    }

if (-not $ExistingTypes) {
     class CMKConnection {
        [string] $Hostname
        [string] $Sitename  
        [string] $Username
        [securestring] $Secret
        [string] $BaseUrl
        [datetime] $ConnectedAt
        [datetime] $LastUsed
        [int] $TimeoutMinutes
        [bool] $SkipCertificateCheck
        [hashtable] $SessionHeaders
        [bool] $IsValid

        # Konstruktor
        CMKConnection([string]$Hostname, [string]$Sitename, [string]$Username, [securestring]$Secret) {
            $this.Hostname = $Hostname
            $this.Sitename = $Sitename
            $this.Username = $Username
            $this.Secret = $Secret
            $this.BaseUrl = "https://$Hostname/$Sitename/check_mk/api/1.0"
            $this.TimeoutMinutes = 60
            $this.SkipCertificateCheck = $false
            $this.ConnectedAt = Get-Date
            $this.LastUsed = Get-Date
            $this.IsValid = $false
        }

        # Sichere Header-Generierung ohne Passwort-Extraktion
        [hashtable] GetHeaders([string]$IfMatch) {
            $this.LastUsed = Get-Date
            
            # Sichere Passwort-Konvertierung nur wenn nötig
            $password = [System.Net.NetworkCredential]::new("", $this.Secret).Password
            
            $headers = @{
                'Authorization' = "Bearer $($this.Username) $password"
                'Accept' = 'application/json'
                'Content-Type' = 'application/json'
            }
            
            if ($IfMatch) {
                $headers['If-Match'] = $IfMatch
            }
            
            # Passwort aus Memory löschen
            $password = $null
            [System.GC]::Collect()
            
            return $headers
        }

        # Connection-Gültigkeitsprüfung
        [bool] IsConnectionValid() {
            if (-not $this.IsValid) { return $false }
            
            $timeSinceLastUse = (Get-Date) - $this.LastUsed
            return $timeSinceLastUse.TotalMinutes -lt $this.TimeoutMinutes
        }

        # Teste die Verbindung
        [bool] TestConnection() {
            try {
                # Netzwerk-Test
                if (-not (Test-NetConnection -ComputerName $this.Hostname -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded) {
                    Write-Verbose "$($this.Hostname) ist nicht über Port 443 erreichbar"
                    return $false
                }

                # API-Test mit /version endpoint
                $headers = $this.GetHeaders($null)
                $response = Invoke-WebRequest -Uri "$($this.BaseUrl)/version" -Headers $headers -Method Get -UseBasicParsing
                
                if ($response.StatusCode -eq 200) {
                    $this.IsValid = $true
                    $this.ConnectedAt = Get-Date
                    return $true
                }
            }
            catch {
                Write-Verbose "Connection test failed: $($_.Exception.Message)"
                $this.IsValid = $false
                return $false
            }
            
            return $false
        }
    }
}

function Connect-CMK {
    <#
    .SYNOPSIS
        Stellt eine sichere Verbindung zur CheckMK REST API her
    
    .DESCRIPTION
        Erstellt eine persistente, sichere Verbindung zur CheckMK REST API mit verbessertem
        Session-Management und Credential-Handling. Unterstützt verschiedene Authentifizierungsmethoden.
    
    .PARAMETER Hostname
        DNS-Name oder IP-Adresse des CheckMK-Servers
    
    .PARAMETER Sitename
        Name der CheckMK-Site/Instanz
    
    .PARAMETER Username
        Benutzername (vorzugsweise Automation User)
    
    .PARAMETER Secret
        Passwort als SecureString
    
    .PARAMETER Credential
        PSCredential-Objekt (Alternative zu Username/Secret)
    
    .PARAMETER UseHTTPS
        Erzwingt HTTPS-Verbindung (Standard: true)
    
    .PARAMETER Port
        Port für die Verbindung (Standard: 443 für HTTPS, 80 für HTTP)
    
    .PARAMETER SkipCertificateCheck
        Überspringt Zertifikatsprüfung (nur für Test-Umgebungen)
    
    .PARAMETER TimeoutMinutes
        Session-Timeout in Minuten (Standard: 60)
    
    .PARAMETER TestConnection
        Testet die Verbindung beim Aufbau
    
    .EXAMPLE
        $connection = Connect-CMK -Hostname "checkmk.example.com" -Sitename "prod" -Username "automation" -Secret $securePassword
    
    .EXAMPLE
        $cred = Get-Credential
        $connection = Connect-CMK -Hostname "192.168.1.100" -Sitename "test" -Credential $cred -SkipCertificateCheck
    #>
    [CmdletBinding(DefaultParameterSetName = 'UserSecret')]
    [OutputType([CMKConnection])]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'DNS-Name oder IP-Adresse des CheckMK-Servers')]
        [ValidateNotNullOrEmpty()]
        [string] $Hostname,

        [Parameter(Mandatory = $true, HelpMessage = 'Name der CheckMK-Site/Instanz')]
        [ValidateNotNullOrEmpty()]
        [string] $Sitename,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserSecret', HelpMessage = 'Benutzername für CheckMK API')]
        [string] $Username,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserSecret', HelpMessage = 'Passwort als SecureString')]
        [securestring] $Secret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential', HelpMessage = 'PSCredential-Objekt')]
        [pscredential] $Credential,

        [Parameter(Mandatory = $false, HelpMessage = 'Verwende HTTPS (empfohlen)')]
        [bool] $UseHTTPS = $true,

        [Parameter(Mandatory = $false, HelpMessage = 'Port für die Verbindung')]
        [ValidateRange(1, 65535)]
        [int] $Port,

        [Parameter(Mandatory = $false, HelpMessage = 'Überspringe Zertifikatsprüfung (nur für Test-Umgebungen)')]
        [switch] $SkipCertificateCheck,

        [Parameter(Mandatory = $false, HelpMessage = 'Session-Timeout in Minuten')]
        [ValidateRange(1, 1440)]
        [int] $TimeoutMinutes = 60,

        [Parameter(Mandatory = $false, HelpMessage = 'Teste Verbindung beim Aufbau')]
        [switch] $TestConnection
    )

    # Parameter-Setup basierend auf ParameterSet
    switch ($PSCmdlet.ParameterSetName) {
        'Credential' {
            $Username = $Credential.UserName
            $Secret = $Credential.Password
        }
        'UserSecret' {
            # Username und Secret bereits gesetzt
        }
    }

    # Standard-Username falls nicht gesetzt
    if (-not $Username) {
        $Username = $env:USERNAME
        Write-Verbose "Verwende aktuellen Benutzer: $Username"
    }

    # Port-Setup
    if (-not $Port) {
        $Port = if ($UseHTTPS) { 443 } else { 80 }
    }

    # URL-Setup
    $protocol = if ($UseHTTPS) { "https" } else { "http" }
    $baseUrl = if ($Port -in @(80, 443)) {
        "$protocol`://$Hostname/$Sitename/check_mk/api/1.0"
    } else {
        "$protocol`://$Hostname`:$Port/$Sitename/check_mk/api/1.0"
    }

    # Certificate Policy für PowerShell 5.x
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion -like '5.*') {
        Set-CertificateValidationPolicy
    }

    # Connection-Objekt erstellen
    try {
        $connection = [CMKConnection]::new($Hostname, $Sitename, $Username, $Secret)
        $connection.BaseUrl = $baseUrl
        $connection.TimeoutMinutes = $TimeoutMinutes
        $connection.SkipCertificateCheck = $SkipCertificateCheck.IsPresent

        # Verbindungstest falls gewünscht
        if ($TestConnection.IsPresent) {
            Write-Verbose "Teste Verbindung zu $baseUrl..."
            
            if (-not $connection.TestConnection()) {
                throw "Verbindungstest zu $Hostname/$Sitename fehlgeschlagen"
            }
            
            Write-Verbose "Verbindung erfolgreich getestet"
        }

        # Globale Connection für Backward-Compatibility
        $Global:CMKConnection = $connection

        Write-Verbose "CheckMK-Verbindung erfolgreich aufgebaut zu $($connection.BaseUrl)"
        return $connection
    }
    catch {
        Write-Error "Fehler beim Verbindungsaufbau: $($_.Exception.Message)"
        throw
    }
}

function Disconnect-CMK {
    <#
    .SYNOPSIS
        Beendet die CheckMK-Verbindung sicher
    
    .DESCRIPTION
        Löscht sensitive Daten aus dem Memory und beendet die Session
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Connection-Objekt zum Beenden')]
        [CMKConnection] 
        $Connection = $Global:CMKConnection
    )

    if ($Connection) {
        # Sensitive Daten löschen
        $Connection.Secret = $null
        $Connection.SessionHeaders = $null
        $Connection.IsValid = $false
        
        # Globale Variable löschen
        if ($Global:CMKConnection -eq $Connection) {
            Remove-Variable -Name CMKConnection -Scope Global -Force -ErrorAction SilentlyContinue
        }
        
        # Garbage Collection
        [System.GC]::Collect()
        
        Write-Verbose "CheckMK-Verbindung beendet"
    }
}

function Test-CMKConnection {
    <#
    .SYNOPSIS
        Testet eine CheckMK-Verbindung
    
    .DESCRIPTION
        Überprüft ob eine CheckMK-Verbindung noch gültig und funktionsfähig ist
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Connection-Objekt zum Testen')]
        [CMKConnection] 
        $Connection = $CMKConnection
    )

    if (-not $Connection) {
        Write-Verbose "Keine Connection übergeben"
        return $false
    }

    if (-not $Connection.IsConnectionValid()) {
        Write-Verbose "Connection ist abgelaufen oder ungültig"
        return $false
    }

    return $Connection.TestConnection()
}

# Verbesserte API-Call Funktion mit automatischer Session-Verwaltung
function Invoke-CMKApiCall {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestMethod] $Method,
        
        [Parameter(Mandatory = $true, HelpMessage = 'Sub-URI der API Funktion (mit / ab der Versionsangabe)')]
        [ValidateNotNullOrEmpty()]
        [string] $Uri,
        
        [Parameter(Mandatory = $true)]
        [CMKConnection] $Connection,
        
        [Parameter(Mandatory = $false)]
        [object] $Body,
        
        [Parameter(Mandatory = $false)]
        [switch] $EndpointReturnsList,
        
        [Parameter(Mandatory = $false, HelpMessage = 'ETag für If-Match Header')]
        [string] $IfMatch
    )

    # Session-Gültigkeit prüfen
    if (-not $Connection.IsConnectionValid()) {
        Write-Verbose "Session abgelaufen, teste Verbindung neu..."
        
        if (-not $Connection.TestConnection()) {
            throw "CheckMK-Verbindung ist nicht mehr gültig. Bitte neu verbinden mit Connect-CMK."
        }
    }

    # Headers abrufen
    $headers = $Connection.GetHeaders($IfMatch)
    
    # Request-Parameter vorbereiten
    $requestParams = @{
        Uri = "$($Connection.BaseUrl)$Uri"
        Method = $Method
        Headers = $headers
        UseBasicParsing = $true
    }

    # Body hinzufügen falls vorhanden
    if ($Body) {
        if ($Body -is [string]) {
            $requestParams.Body = $Body
        } else {
            $requestParams.Body = $Body | ConvertTo-Json -Depth 10
        }
    }

    # Certificate Check für PowerShell 7+
    if ($Connection.SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 7) {
        $requestParams.SkipCertificateCheck = $true
    }

    try {
        Write-Verbose "$Method $($requestParams.Uri)"
        
        $response = Invoke-WebRequest @requestParams
        
        Write-Verbose "Response: $($response.StatusCode) $($response.StatusDescription)"
        
        # Erfolgreiche Antwort verarbeiten
        if ($response.StatusCode -eq 200) {
            $checkMKObject = ($response.Content | ConvertFrom-Json)
            
            # ETag hinzufügen falls vorhanden
            if ($response.Headers.ETag) {
                $checkMKObject | Add-Member -MemberType NoteProperty -Name ETag -Value $response.Headers.ETag -Force
            }

            if ($EndpointReturnsList.IsPresent -and $checkMKObject.Value) {
                return $checkMKObject.Value
            } else {
                return $checkMKObject
            }
        }
        elseif (@('Post', 'Delete', 'Put') -contains $Method -and $response.StatusCode -eq 204) {
            # 204 No Content - Erfolgreiche Operation ohne Rückgabe
            return $true
        }
        else {
            throw "Unerwarteter Status Code: $($response.StatusCode)"
        }
    }
    <#
    PS5 kennt Typ nicht und wirft Fehler
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        # PowerShell 7+ HTTP Fehler
        $errorResponse = $_.Exception.Response
        $errorContent = ""
        
        if ($errorResponse.Content) {
            $errorContent = $errorResponse.Content | ConvertFrom-Json | ConvertTo-Json -Depth 3
        }
        
        $errorMessage = "HTTP $([int]$errorResponse.StatusCode) $($errorResponse.ReasonPhrase)"
        if ($errorContent) {
            $errorMessage += "`nDetails: $errorContent"
        }
        
        throw $errorMessage
    }
    #>
    catch [System.Net.WebException] {
        # PowerShell 5.x HTTP Fehler
        $ErrMessage =  $_.ErrorDetails.Message;
        Write-Verbose "An exception was caught: $($_.Exception.Message)"
        $ResponseErrorObj = $_.Exception.Response # Nur BaseResponse bei Exceptions möglich
        Add-Member -InputObject $ResponseErrorObj -NotePropertyName ErrorMessage -NotePropertyValue $ErrMessage # add catched error message to $BaseResponse object
        throw ($ResponseErrorObj | Out-String)
    }
}

function Set-CertificateValidationPolicy {
    # Alternative zu invoke-webRequest -SkipCertificateCheck, welches es nur in PowerShell 7 gibt
    # Die Änderung soll nur in PS5 erfolgen. Ab PS7 bitte den Schalter an Invoke-Webrequest nutzen
    If ($PSVersionTable.PSVersion -like '5.*') {
        If ([System.Net.ServicePointManager]::CertificatePolicy.GetType().Name -eq 'DefaultCertPolicy') {
            class TrustAllCertsPolicy : System.Net.ICertificatePolicy {
                [bool] CheckValidationResult (
                    [System.Net.ServicePoint]$srvPoint,
                    [System.Security.Cryptography.X509Certificates.X509Certificate]$certificate,
                    [System.Net.WebRequest]$request,
                    [int]$certificateProblem
                ) {
                    return $true
                }
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
        }
    }
}

function Get-CMKHeader {
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential', HelpMessage = 'DNS-Name des CheckMK-Servers')]
        [Parameter(Mandatory = $true, ParameterSetName = 'UserPassword', HelpMessage = 'DNS-Name des CheckMK-Servers')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Hostname,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential', HelpMessage = 'Instanz auf dem CheckMK-Server')]
        [Parameter(Mandatory = $true, ParameterSetName = 'UserPassword', HelpMessage = 'Instanz auf dem CheckMK-Server')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Sitename,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserPassword', HelpMessage = 'Benutzer mit genügend API-Rechten in CheckMK.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username,

        [Parameter(Mandatory = $true, ParameterSetName = 'UserPassword', HelpMessage = 'Passwort zum Zugriff auf die CheckMK API.')]
        [ValidateNotNullOrEmpty()]
		[SecureString]
		$Secret,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential', HelpMessage = 'Credential Objekt zur Authentifizierung and der CheckMK-API')]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        $Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential', HelpMessage = 'Wenn bestehende Objekte bearbeitet werden sollen, muss das ETag des Objektes zuvor abgerufen und bei der Änderungsanfrage in den Header eingefügt werden.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'UserPassword', HelpMessage = 'Wenn bestehende Objekte bearbeitet werden sollen, muss das ETag des Objektes zuvor abgerufen und bei der Änderungsanfrage in den Header eingefügt werden.')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IfMatch
    )

	# Ab PS7 wird ConvertFrom-SecureString möglich
    $password = [System.Net.NetworkCredential]::new("", $Secret).Password

    if ($PSCmdlet.ParameterSetName -eq 'Credential') {
        $Username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
    }

    $header = New-Object -TypeName 'System.Collections.Generic.Dictionary[[string],[string]]'
    $header.Add('Authorization', "Bearer $username $password")
    $header.Add('Accept', 'application/json')
    $header.Add('Content-Type', 'application/json')
    if ($IfMatch) {
        $header.Add('If-Match', $IfMatch)
    }
    return $header
}
function Invoke-CustomWebRequest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [Parameter(Mandatory = $true)]
        [Object]
        $Headers,

        [Parameter(Mandatory = $false)]
        [object]
        $Body
    )
    # Diese Funktion ist notwendig, da Invoke-WebRequest bei Statuscodes -ne 200 einen Fehler wirft.
    # Mit Powershell 7 erhält Invoke-Webrequest einen neuen Parameter: -SkipHttpErrorCheck. Damit wäre das hier vermutlich überflüssig.
    Set-CertificateValidationPolicy
    $PSBoundParameters.Add('UseBasicParsing', $true)
    $BaseResponse = try {
        $PrimaryResponse = Invoke-WebRequest @PSBoundParameters
        $PrimaryResponse.BaseResponse
        }
        catch [System.Net.WebException] {
            $ErrMessage =  $_.ErrorDetails.Message;
            Write-Verbose "An exception was caught: $($_.Exception.Message)"
            $ResponseErrorObj = $_.Exception.Response # Nur BaseResponse bei Exceptions möglich
            Add-Member -InputObject $ResponseErrorObj -NotePropertyName ErrorMessage -NotePropertyValue $ErrMessage #add catched error message to $BaseResponse object
            $ResponseErrorObj
        }
    $ResponseHash = @{
        BaseResponse = $BaseResponse
        Response     = $PrimaryResponse
    }
    $ResponseObject = New-Object -TypeName psobject -Property $ResponseHash
    return $ResponseObject
}
#endregion Connection

#region Main
function Get-CMKServerInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    return Invoke-CMKApiCall -Method Get -Uri '/version' -Connection $Connection
}
function Get-CMKPendingChanges {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    return Invoke-CMKApiCall -Method Get -Uri '/domain-types/activation_run/collections/pending_changes' -Connection $Connection
}
function Invoke-CMKChangeActivation {
    [CmdletBinding()]
    param(
	    [Parameter(Mandatory = $true, HelpMessage = 'Abgerufen mit Get-CMKPendingChanges')]
        [object]
        $PendingChanges,

        [Parameter(Mandatory = $false, HelpMessage = 'Sollen durch andere Nutzer durchgeführte Änderungen mit Aktiviert werden? Pflicht, wenn es welche gibt.')]
        [switch]
        $ForceForeignChanges,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    $activateChanges = @{
        force_foreign_changes = $ForceForeignChanges.IsPresent
        redirect              = $false
        sites                 = [array]$Connection.Sitename
    } | ConvertTo-Json

    try {
        $CheckMKActivationObject = Invoke-CMKApiCall -Method Post -Uri '/domain-types/activation_run/actions/activate-changes/invoke' -Body $activateChanges -Connection $Connection -IfMatch $PendingChanges.Etag
    }
    catch {
        if ($($_.Exception.Message) -match "Currently there are no changes to activate.") {
            Write-Warning "Currently there are no changes to activate."
            return $true
        }
        else {
            Write-Error "Changes could not be activated. Error message: $($_.Exception.Message)"
        }
    }
    if (-not $CheckMKActivationObject) {
        return $false
    }
    $AttemptForCompletion = 0
    $maximumAttemptsForCompletion = 14 # Den Wert ggf. noch anpassen. Vielleicht dauern Aktivierungen ja regelmäßig länger.
    do {
        Start-Sleep -Seconds 3
        $AttemptForCompletion++
        $activationStatus = Invoke-CMKApiCall -Method Get -Uri "/objects/activation_run/$($CheckMKActivationObject.id)" -Connection $Connection
        $result = [string]($activationStatus.title).split(' ')[-1].replace('.', '')
    }
    until (([bool]($activationStatus.extensions.is_running) -eq $false) -or ($AttemptForCompletion -gt $maximumAttemptsForCompletion))
    If (($result -ne 'complete')) {
        Write-Verbose "Die Aktivierung der Änderungen konnte nicht innerhalb von $maximumAttemptsForCompletion abgeschlossen werden. Result: $Result"
        return $false
    }
}
#endregion Main
#region Hosts
function Get-CMKHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Spezifisch')]
        [ValidateNotNullOrEmpty()]
        [string]
        $HostName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Spezifisch')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Liste')]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    If ($PSCmdlet.ParameterSetName -eq 'Spezifisch') {
        return Invoke-CMKApiCall -Method Get -Uri "/objects/host_config/$($HostName)" -Connection $Connection
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Liste') {
        return Invoke-CMKApiCall -Method Get -Uri '/domain-types/host_config/collections/all' -Connection $Connection -EndpointReturnsList
    }
}
function New-CMKHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $HostName,

        [Parameter(Mandatory = $true, HelpMessage = 'Pfad zum Ordner. Anstelle von Slash bitte Tilde ~ benutzen. Case-Sensitive. Entspricht dem Attribut id im Objekt von Get-CheckMKFolder.')]
        [string]
        $FolderPath,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    $newHost = @{
        folder    = "$FolderPath"
        host_name = "$($HostName)"
    } | ConvertTo-Json
    return Invoke-CMKApiCall -Method Post -Uri '/domain-types/host_config/collections/all' -Body $newHost -Connection $Connection
}
function New-CMKClusterHost {
<#
    .SYNOPSIS
        Add cluster to checkmk
    .DESCRIPTION
        Add cluster to checkmk
    .PARAMETER FolderPath
        The path name of the folder in WATO. case sensitive. corresponds to "id" attribute in Get-CheckMKFolder.
        example: "~servers/linux"
    .PARAMETER Nodes
        an array of nodes 
    .PARAMETER Attributes
        define attributes like alias, tags, custom variables.
        example:
        @{
            alias = "PLUTO"
            tag_criticality = "test"
        }
    .EXAMPLE
        $ClusterAttributes = @{
            alias = "MYCLUSTER"
            tag_criticality = "test"
        }
        New-CMKClusterHost -Connection $CMKConn -Hostname mycluster.example -FolderPath "~clusters" -Nodes 'node1','node2' -Attributes $ClusterAttributes
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $HostName,

        [Parameter(Mandatory = $true, HelpMessage = 'Pfad zum Ordner. Anstelle von Slash bitte Tilde ~ benutzen. Case-Sensitive. Entspricht dem Attribut id im Objekt von Get-CheckMKFolder.')]
        [string]
        $FolderPath,

        [Parameter(Mandatory = $true)]
        [string[]]
        $Nodes,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection,

        [Parameter(Mandatory = $false, HelpMessage = 'Hashtable @{attribute = "value"; attr2 = "value"} siehe https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/#/Hosts/cmk.gui.plugins.openapi.endpoints.host_config.create_host')]
        $Attributes = @{}
    )
    $newCluster = @{
        folder    = "$FolderPath"
        host_name = "$($HostName)"
        nodes = $Nodes
        attributes = $Attributes
    } | ConvertTo-Json
    try {
        return Invoke-CMKApiCall -Method Post -Uri '/domain-types/host_config/collections/clusters' -Body $newCluster -Connection $Connection
    }
    catch {
        if ($($_.Exception.Message) -match ".*Host .* already exists.") {
            Write-Warning "Cluster Host already exists. `r`nFull error message:`r`n$($_.Exception.Message)"
        }
        else {
            Write-Error "Cluster host could not be created in checkmk. `r`nError message:`r`n$($_.Exception.Message)"
        }
    }
}
function Rename-CMKHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMKHost abgerufen')]
        [object]
        $HostObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $newHostName,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    # Ist langsam. Behindert den Betrieb von CheckMK (Server steht während der Zeit). Dauer: ca 30 Sekunden
    # Im Anschluss: Invoke-CMKChangeActivation
    $newName = @{
        new_name = $newHostName
    } | ConvertTo-Json
    return Invoke-CMKApiCall -Method Put -Uri "/objects/host_config/$($HostObject.id)/actions/rename/invoke" -Body $newName -Connection $Connection -IfMatch $HostObject.Etag
}
function Update-CMKHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMKHost abgerufen')]
        [object]
        $HostObject,

        [Parameter(Mandatory = $true, HelpMessage = 'Lies die Doku! https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/#/Hosts/cmk.gui.plugins.openapi.endpoints.host_config.update_host')]
        $Changeset,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    # https://<CheckMK-Host>/<sitename>/check_mk/api/1.0/ui/#/Hosts/cmk.gui.plugins.openapi.endpoints.host_config.update_host
    return Invoke-CMKApiCall -Method Put -Uri "/objects/host_config/$($HostObject.id)" -Body $Changeset -Connection $Connection -IfMatch $HostObject.Etag
}
function Remove-CMKHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HostName,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    return Invoke-CMKApiCall -Method Delete -Uri "/objects/host_config/$HostName" -Connection $Connection
}
#endregion Hosts
#region Hosts Hilfsfunktionen
function Set-CMKHostAttribute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMKHost abgerufen', ParameterSetName = 'Update')]
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMKHost abgerufen', ParameterSetName = 'Remove')]
        [object]
        $HostObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Update')]
        [Alias('SetAttribute')]
        [string]
        $UpdateAttribute,

        [Parameter(Mandatory = $true, ParameterSetName = 'Update')]
        $Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
        [string]
        $RemoveAttribute,

        [Parameter(Mandatory = $false, ParameterSetName = 'Update')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remove')]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    #Hinweis zu Custom Host Attributes: Diese lassen sich anlegen und bearbeiten, aber nicht löschen. Da ist die API noch fehlerhaft.
    $Changeset = @{}
    If ($PSCmdlet.ParameterSetName -eq 'Update') {
        $Changeset.update_attributes = @{
            $UpdateAttribute = $Value
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Remove') {
        $Changeset.remove_attributes = [array]("$RemoveAttribute")
    }
    $Changeset = $Changeset | ConvertTo-Json
    return Update-CMKHost -HostObject $HostObject -Changeset $Changeset -Connection $Connection
}
function Add-CMKHostLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]
        $HostObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Value,
        
        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    $Labels = @{}
    If ($HostObject.extensions.attributes.labels) {
        Foreach ($Pair in ($HostObject.extensions.attributes.labels.PSObject.Members | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' })) {
            $Labels.add($Pair.Name, $Pair.Value)
        }
    }
    If ($Labels.$Key) {
        Write-Verbose "Der Schlüssel $Key ist auf $($HostObject.id) bereits vorhanden"
        return $false
    }
    else {
        $Labels.Add($Key, $Value)
        return Set-CMKHostAttribute -HostObject $HostObject -UpdateAttribute 'labels' -Value $Labels -Connection $Connection
    }
}
function Remove-CMKHostLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]
        $HostObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    If ($HostObject.extensions.attributes.labels) {
        $Labels = @{}
        Foreach ($Pair in ($HostObject.extensions.attributes.labels.PSObject.Members | Where-Object -FilterScript { $_.MemberType -eq 'NoteProperty' })) {
            $Labels.add($Pair.Name, $Pair.Value)
        }
        $Labels.Remove($Key)
        If ($Labels.Count -gt 0) {
            return Set-CMKHostAttribute -HostObject $HostObject -UpdateAttribute 'labels' -Value $Labels -Connection $Connection
        }
        else {
            return Set-CMKHostAttribute -HostObject $HostObject -RemoveAttribute 'labels' -Connection $Connection
        }
    }
    else {
        Write-Verbose "Auf Host $($HostObject.id) sind keine Labels vorhanden"
        return $false
    }
}
#endregion Hosts Hilfsfunktionen
#region Folders
function Get-CMKFolder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Pfad zum Ordner. Anstelle von Slash bitte Tilde ~ benutzen. Case-Sensitive. Entspricht dem Attribut id im zurückerhaltenen Objekt.', ParameterSetName = 'Spezifisch')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ If ( ($_ -notmatch '^~.*$') -or ($_.ToCharArray() -contains @('/', '\')) ) { throw 'Der Ordnerpfad ist nicht wohlgeformt.' } $true })]
        [string]
        $FolderPath,

        [Parameter(Mandatory = $false, HelpMessage = 'Liste der Hosts im Ordner einschließen', ParameterSetName = 'Spezifisch')]
        [switch]
        $ShowHosts,

        [Parameter(Mandatory = $false, ParameterSetName = 'Spezifisch')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Liste')]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    If ($PSCmdlet.ParameterSetName -eq 'Spezifisch') {
        If ($ShowHosts.IsPresent) {
            $ShowHosts_bool = 'true'
        }
        else {
            $ShowHosts_bool = 'false'
        }
        return Invoke-CMKApiCall -Method Get -Uri "/objects/folder_config/$($FolderPath)?show_hosts=$($ShowHosts_bool)" -Connection $Connection
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Liste') {
        return Invoke-CMKApiCall -Method Get -Uri '/domain-types/folder_config/collections/all?recursive=true&show_hosts=false' -Connection $Connection -EndpointReturnsList

    }
}
#endregion Folders
#region Downtimes
function Get-CMKDowntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Downtimes nur dieses Hosts abfragen')]
        [string]
        $HostName,

        <#[parameter(HelpMessage = 'Downtimes nur dieses Service abfragen. Case-Sensitive')]
        [string]
        $ServiceDescription,#>
        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    $QueryExtension = ''
    If ($HostName -or $ServiceDescription) {
        $QueryExtension += '?'
    }
    <#If ($ServiceDescription) {
        $QueryExtension += "service_description=$($ServiceDescription)"
    }
    If ($HostName -and $ServiceDescription) {
        $QueryExtension += '&'
    }#>
    If ($HostName) {
        $QueryExtension += "host_name=$($HostName)"
    }
    return Invoke-CMKApiCall -Method Get -Uri "/domain-types/downtime/collections/all$($QueryExtension)" -Connection $Connection -EndpointReturnsList
}
function New-CMKDowntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'onHost', HelpMessage = 'Die Downtime wird für den genannten Host gesetzt')]
        [Parameter(Mandatory = $true, ParameterSetName = 'onService', HelpMessage = 'Die Downtime wird für die genannten Services dieses Hosts gesetzt')]
        [ValidateNotNullOrEmpty()]
        [string]
        $HostName,

        [Parameter(Mandatory = $true, ParameterSetName = 'onService', HelpMessage = 'Die Downtime wird nur für angegebene Services gesetzt (Case Sensitive)' )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ServiceDescriptions,

        [Parameter(Mandatory = $false, ParameterSetName = 'onHost', HelpMessage = 'Startzeitpunkt ist optional. Wenn nicht befüllt wird die aktuelle Zeit als Start definiert.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'onService', HelpMessage = 'Startzeitpunkt ist optional. Wenn nicht befüllt wird die aktuelle Zeit als Start definiert.')]
        [datetime]
        $StartTime = (Get-Date),

        # EndTime muss zwingend nach StartDate liegen. Ist das nicht der Fall wird kein Fehler gemeldet, CMK legt ohne Fehlermeldung keine Downtime an.
        [Parameter(Mandatory = $true, ParameterSetName = 'onHost', HelpMessage = 'Endzeitpunkt ist nicht optional.')]
        [Parameter(Mandatory = $true, ParameterSetName = 'onService', HelpMessage = 'Endzeitpunkt ist nicht optional.')]
        [ValidateScript({
            if ($_ -gt (Get-Date) -and $_ -gt $StartTime) {
                $true
            }else {
                throw "$_ ist kein valider Wert. Endzeitpunkt muss nach dem Startdatum und in der Zukunft liegen."
                # Geht nur mit PS6+
                # ErrorMessage = "{0} ist kein valider Wert. Endzeitpunkt muss nach dem Startdatum und in der Zukunft liegen."
            }
        })]
        [datetime]
        $EndTime,

        [Parameter(Mandatory = $false, ParameterSetName = 'onHost')]
        [Parameter(Mandatory = $false, ParameterSetName = 'onService')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Comment,

        [Parameter(Mandatory = $false, ParameterSetName = 'onHost', HelpMessage = 'Dauer in Minuten. Downtime beginnt erst mit Statuswechsel und gilt für die angegebene Duration. Default ist 0.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'onService', HelpMessage = 'Dauer in Minuten. Downtime beginnt erst mit Statuswechsel und gilt für die angegebene Duration. Default ist 0.')]
        [ValidateRange(0,[int]::MaxValue)]
        [int]
        $Duration,

        [Parameter(Mandatory = $false, ParameterSetName = 'onHost')]
        [Parameter(Mandatory = $false, ParameterSetName = 'onService')]
        [object]
        $Connection
    )
    $Downtime = @{
        start_time = ($StartTime | Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz') #Format ISO 8601 für CheckMK erforderlich
        end_time   = ($EndTime | Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')
        host_name  = "$($HostName)"
    }
    If ($Comment) {
        $Downtime.comment = $Comment
    }
    if ($Duration) {
        $Downtime.duration = $Duration
    }
    If ($PSCmdlet.ParameterSetName -eq 'onHost') {
        $Downtime.downtime_type = 'host'
        $Downtime = $Downtime | ConvertTo-Json
        $URI = '/domain-types/downtime/collections/host'
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'onService') {
        $Downtime.downtime_type = 'service'
        $Downtime.service_descriptions = [array]$ServiceDescriptions
        $Downtime = $Downtime | ConvertTo-Json
        $URI = '/domain-types/downtime/collections/service'
    }

    Write-Verbose -Message $Downtime

    return Invoke-CMKApiCall -Method Post -Uri $URI -Body $Downtime -Connection $Connection
}
function Remove-CMKDowntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'byID')]
        [int]
        $ID,

        [Parameter(Mandatory = $true, ParameterSetName = 'byHostName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'byHostNameAndServiceDescriptions')]
        [string]
        $HostName,

        [Parameter(Mandatory = $true, ParameterSetName = 'byHostNameAndServiceDescriptions')]
        [string[]]
        $ServiceDescriptions,

        [Parameter(Mandatory = $false, ParameterSetName = 'byHostName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'byID')]
        [Parameter(Mandatory = $false, ParameterSetName = 'byHostNameAndServiceDescriptions')]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    $Delete = @{}
    If ($PSCmdlet.ParameterSetName -eq 'byID') {
        $Delete.delete_type = 'by_id'
        $Delete.downtime_id = "$ID"
		$Delete.site_id = "$($Connection.sitename)"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'byHostName') {
        $Delete.delete_type = 'params'
        $Delete.host_name = "$($HostName)"

    }
    elseif ($PSCmdlet.ParameterSetName -eq 'byHostNameAndServiceDescriptions') {
        $Delete.delete_type = 'params'
        $Delete.host_name = "$($HostName)"
        $Delete.service_descriptions = [array]$ServiceDescriptions

    }
    $Delete = $Delete | ConvertTo-Json
    return Invoke-CMKApiCall -Method Post -Uri '/domain-types/downtime/actions/delete/invoke' -Body $Delete -Connection $Connection
}
#endregion Downtimes

#region Services
function Get-CMKService {
<#
    .SYNOPSIS
        Retrieve status of services
    .DESCRIPTION
        retrieve status of services. Filter by host name, state and/or regular expression on service description using parameter -DescriptionRegExp.
    .PARAMETER DescriptionRegExp
        filter on service description by regular expression
    .PARAMETER State
        filter on service state (CRIT, WARN, OK, UNKNOWN)
        multiple choices are possible
    .PARAMETER Columns 
        control which fields should be returned
    .PARAMETER HostName
        control services of which host should be returned
    .EXAMPLE
        Get-CMKService -HostName myhost.domain.example -Connection $Connection
            List all services of one host.
    .EXAMPLE
        Get-CMKService -DescriptionRegExp "^Filesystem(.)+" -Columns host_name, description, state -Connection $Connection
            List all services of all hosts beginning with "Filesystem" and output host_name, description and state
    .EXAMPLE
        Get-CMKService -DescriptionRegExp "^Filesystem(.)+" -State CRIT, WARN -Columns host_name, description, state -Connection $Connection
            List all services beginning with "Filesystem", having state CRIT or WARN and output host_name, description and state
    .EXAMPLE
        Get-CMKService -State CRIT -Connection $Connection
            List all services having a critical state.
            Output default columns: host_name and description
    .EXAMPLE
        Get-CMKService -HostGroup MariaDB, OracleDB -State CRIT -Connection $Connection
            List all services from host_groups "MariaDB" OR "OracleDB" having a critical state. 
    .LINK
        https://<CheckMK-Host>/<sitename>/check_mk/openapi/#operation/cmk.gui.plugins.openapi.endpoints.service._list_all_services
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'byHostName', HelpMessage = 'Zeige Services nur eines Hosts')]
        $HostName,

        [Parameter(Mandatory = $false, ParameterSetName = 'byHostName', HelpMessage = 'Filter-Ausdruck für service description als regular expression. Beispiel: "^Filesystem(.)+" (listet alle Services auf, die mit "Filesystem" beginnen)')]
        [Parameter(Mandatory = $false, ParameterSetName = 'All', HelpMessage = 'Filter-Ausdruck für service description als regular expression. Beispiel: "^Filesystem(.)+" (listet alle Services auf, die mit "Filesystem" beginnen)')]
        [ValidateNotNullOrEmpty()]
        $DescriptionRegExp,

        [Parameter(Mandatory = $false, ParameterSetName = 'byHostName', HelpMessage = 'Filter auf Service state (OK, WARN, CRIT, UNKNOWN)')]
        [Parameter(Mandatory = $false, ParameterSetName = 'All', HelpMessage = 'Filter auf Service state (OK, WARN, CRIT, UNKNOWN)')]
        [ValidateSet('', 'OK', 'WARN', 'CRIT', 'UNKNOWN')]
        [string[]]$State,

        [Parameter(Mandatory = $false, ParameterSetName = 'byHostName', HelpMessage = 'Filter host_groups, multiple values accepted (link using logical OR), case-insensitive equality')]
        [Parameter(Mandatory = $false, ParameterSetName = 'All', HelpMessage = 'Filter host_groups, multiple values accepted (link using logical OR), case-insensitive equality')]
        [string[]]$HostGroup,

        [Parameter(Mandatory = $false, ParameterSetName = 'byHostName', HelpMessage = 'auszugebende Felder')]
        [Parameter(Mandatory = $false, ParameterSetName = 'All', HelpMessage = 'auszugebende Felder')]
        [ValidateSet('host_name', 'description', 'state', 'plugin_output', 'host_groups')]
        $Columns = @('host_name', 'description'),

        [Parameter(Mandatory = $false, ParameterSetName = 'byHostName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [CMKConnection]
        $Connection = $CMKConnection
    )

    $QueryExtension = ''
    [string[]]$QueryExprArray = @()
    
    If ($DescriptionRegExp) {
        $QueryExprArray += "{""op"": ""~"", ""left"": ""description"", ""right"": ""$DescriptionRegExp""}"
    }

    If ($State) {
        $StateExprArray = @()
        #map service state names to numeric state and add to list 
        foreach ($i in $State) {
            $MapState = ""
            switch ($i) {
                'OK' { $MapState = "0" }
                'WARN' { $MapState = "1" }
                'CRIT' { $MapState = "2" }
                'UNKNOWN' { $MapState = "3" }
                Default { Write-Error "state could not be mapped." }
            }
            $StateExprArray += "{""op"": ""="", ""left"": ""state"", ""right"": ""$MapState""}"
        }
        #build query expression
        $StateExprList = $StateExprArray -join "," 
        If ($StateExprArray.Count -gt 1) {
            $StateExpr += "{""op"": ""or"", ""expr"": [$StateExprList]}"
        }
        else {
            $StateExpr += "$StateExprList"
        }
        $QueryExprArray += $StateExpr
    }

    If ($HostGroup) {
        $HostGroupExprArray = @()
        #map service state names to numeric state and add to list 
        foreach ($i in $HostGroup) {
            $HostGroupExprArray += "{""op"": ""<="", ""left"": ""host_groups"", ""right"": ""$i""}"
        }
        #build query expression
        $HostGroupExprList = $HostGroupExprArray -join "," 
        If ($HostGroupExprArray.Count -gt 1) {
            $HostGroupExpr += "{""op"": ""or"", ""expr"": [$HostGroupExprList]}"
        }
        else {
            $HostGroupExpr += "$HostGroupExprList"
        }
        $QueryExprArray += $HostGroupExpr
    }

    If ($QueryExprArray.Count -gt 0 -or $Columns) {
        $QueryExtension += '?'
    }
    
    $QueryExprList = $QueryExprArray -join ","

    #if more than one query expressions are defined, combine with 'and' operator, else use expression directly
    If ($QueryExprArray.Count -gt 1) {
        $QueryExtension += "query={""op"": ""and"", ""expr"": [$QueryExprList]}"
    }
    else {
        #do we have a query?
        If ($QueryExprArray.Count -gt 0) {
        $QueryExtension += "query=$QueryExprList"
        }
    }

    If ($Columns) {
        foreach ($col in $Columns) {
            $QueryExtension += "&columns=$col"
        }
    }

    Write-Verbose $QueryExtension

    If ($PSCmdlet.ParameterSetName -eq 'byHostName') {
        return Invoke-CMKApiCall -Method Get -Uri "/objects/host/$($HostName)/collections/services$($QueryExtension)" -Connection $Connection
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'All') {
        return Invoke-CMKApiCall -Method Get -Uri "/domain-types/service/collections/all$($QueryExtension)" -Connection $Connection -EndpointReturnsList
    }
}

function Get-CMKServiceDiscoveryResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMKHost abgerufen')]
        [string]
        $HostName,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )

    return Invoke-CMKApiCall -Method Get -Uri "/objects/service_discovery/$($HostName)" -Connection $Connection
}

function Invoke-CMKServiceDiscovery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMKHost abgerufen')]
        [string]
        $HostName,

        # refresh is also possible, but apparently produces an undocumented error code for the API call
        [Parameter(Mandatory = $false)]
        [ValidateSet('new','remove','fix_all','tabula_rasa','only_host_labels')]
        [string]
        $Mode = 'fix_all',

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )

    $Body = @{
        host_name = $HostName
        mode = $Mode
    } | ConvertTo-Json

    return Invoke-CMKApiCall -Method Post -Uri '/domain-types/service_discovery_run/actions/start/invoke' -Body $Body -Connection $Connection
}
#endregion Services

#region Users
function Get-CMKUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Spezifisch')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username,

        [Parameter(Mandatory = $false, ParameterSetName = 'Spezifisch')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Liste')]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    
    if ($PSCmdlet.ParameterSetName -eq 'Spezifisch') {
        return Invoke-CMKApiCall -Method Get -Uri "/objects/user_config/$($Username)" -Connection $Connection
    }elseif ($PSCmdlet.ParameterSetName -eq 'Liste') {
        return Invoke-CMKApiCall -Method Get -Uri "/domain-types/user_config/collections/all" -Connection $Connection -EndpointReturnsList
    }
}

function Update-CMKUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMK-User abgerufenes User Objekt')]
        [object]
        $UserObject,

        [Parameter(Mandatory = $true)]
        $Changeset,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    
    Write-Verbose -Message $UserObject
    Write-Verbose -Message $Changeset

    return Invoke-CMKApiCall -Method Put -Uri "/objects/user_config/$($UserObject.Id)" -Body $Changeset -Connection $Connection -IfMatch $UserObject.ETag
}

function Set-CMKUserAttribute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Mit Get-CMK-User abgerufenes User Objekt')]
        [object]
        $UserObject,

        [Parameter(Mandatory = $true)]
        [string]
        $UpdateAttribute,

        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $false)]
        [CMKConnection]
        $Connection = $CMKConnection
    )
    
    $Changeset = @{
        $UpdateAttribute = $Value
    }

    $Changeset = $Changeset | ConvertTo-Json

    return Update-CMKUser -UserObject $UserObject -Changeset $Changeset -Connection $Connection
}
#endregion
$ExportableFunctions = @(
    'Connect-CMK'
    'Disconnect-CMK'
    'Test-CMKConnection'
    'Get-CMKConnection'
    'Invoke-CMKApiCall'
    'Get-CMKServerInfo'
    'Invoke-CMKChangeActivation'
    'Get-CMKHost'
    'New-CMKHost'
    'New-CMKClusterHost'
    'Rename-CMKHost'
    'Update-CMKHost'
    'Remove-CMKHost'
    'Set-CMKHostAttribute'
    'Add-CMKHostLabel'
    'Remove-CMKHostLabel'
    'Get-CMKFolder'
    'Get-CMKDowntime'
    'New-CMKDowntime'
    'Remove-CMKDowntime'
    'Get-CMKPendingChanges'
    'Get-CMKService'
    'Invoke-CMKServiceDiscovery'
    'Get-CMKServiceDiscoveryResult'
    'Get-CMKUser'
    'Update-CMKUser'
    'Set-CMKUserAttribute'
)
Export-ModuleMember -Function $ExportableFunctions