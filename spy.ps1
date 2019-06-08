<#

THIS SCRIPT WAS WRITTEN BY @secfarmer

USAGE: spy.ps1 $IP

#>

param([String] $target)
[console]::BackgroundColor = "black"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$url_scan_apikey = ""
$virustotal_apikey = ""
mkdir ./threatscan-$target

if ([string]::IsNullOrEmpty($target)) {

    Write-Host "Null or Empty Target. Please supply a valid Uri... Exiting" -ForegroundColor Red
    exit(0)
} elseif ($target -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -or $target -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}") {

    Write-Host "Getting VirusTotal report for $target" -ForegroundColor Yellow
    try {

        $params = @{'apikey'=$virustotal_apikey;'ip'=$target}
        $vtscan = Invoke-RestMethod -Uri "https://www.virustotal.com/vtapi/v2/ip-address/report" -Method GET -Body $params
    } catch {

        $_.Exception.Message
    }

    switch ($vtscan.response_code) {

        0{

            Write-Host "Result not present in VirusTotal (Error)" -ForegroundColor Red
        }

        1{

            Write-Host "VirusTotal lookup complete. Retrieving result..." -ForegroundColor Green
            Write-Host ($vtscan | Out-String) -ForegroundColor Yellow
            Write-Host ($vtscan | Out-String | Out-File -Path "./threatscan-$target/vtlookup-$target.txt")
        }

        -2{

            Write-Host "Scanning... URLs submitted via API are lowest priority. " -ForegroundColor Red
        }
    }

    Write-Host "Getting data from Greynoise.io..." -ForegroundColor Green
    try {

        $params = @{'ip'=$target}
        $greynoise = Invoke-RestMethod -Uri "http://api.greynoise.io:8888/v1/query/ip" -Method POST -Body $params

    } catch {

        $_.Exception.Message

    }

    Write-Host "Last Greynoise result for $target :" -ForegroundColor Yellow
    Write-Output ($greynoise.records) | Select-Object * -Last 1 | Write-Host -ForegroundColor Yellow
    Write-Host "Full content logged to text file." -ForegroundColor Green
    $greynoise.records | Select-Object * | Out-File "./threatscan-$target/greynoise-$target.txt"
    
} else {

    Write-Host "$target is not a valid IP address or CIDR. Exiting." -ForegroundColor Red
    exit(0)
}

try {
    
    $urlscan_request = Invoke-WebRequest -Headers @{"Api-Key" = "$url_scan_apikey"} -Method POST ` -Body "{`"url`":`"$target`"}" -Uri "https://urlscan.io/api/v1/scan/" ` -ContentType application/json | ConvertFrom-JSON
    Write-Host "Warning: if $target is not serving a webpage, urlscan.io results might look weird. " -ForegroundColor Yellow
    Write-Host "urlscan.io has completed on $target , sleeping 25 seconds to grab results." -ForegroundColor Green
    Sleep(25)
    $uuid = $urlscan_request.UUID
    Write-Host "Downloading urlscan.io scan log............" -ForegroundColor Red
    Invoke-WebRequest -Uri "https://urlscan.io/api/v1/result/$uuid" -OutFile "./threatscan-$target/URLScan-Data-$uuid.json"
    Write-Host "Complete." -ForegroundColor Green
    Sleep(1)
    Write-Host "Downloading urlscan.io page screenshot............" -ForegroundColor Red
    Invoke-WebRequest -Uri "https://urlscan.io/screenshots/$uuid.png" -OutFile "./threatscan-$target/URLScan-ScreenShot-$uuid.png"
    Write-Host "Complete." -ForegroundColor Green
    Sleep(1)
    Write-Host "Downloading urlscan.io DOM log.........." -ForegroundColor Red
    Invoke-WebRequest -Uri "https://urlscan.io/dom/$uuid/" -OutFile "./threatscan-$target/URLScan-DOM-$uuid.txt"
    Write-Host "Complete." -ForegroundColor Green
    Sleep(1)
    Write-Host ("Script execution complete. Data has been logged in the appropriate directory.")

} catch {

    $_.Exception.Message
    Write-Host "Error, something went wrong. Exiting." -ForegroundColor Red

}

Set-Location $pwd
exit(0)
