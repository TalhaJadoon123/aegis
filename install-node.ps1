$url = "https://nodejs.org/dist/v22.12.0/node-v22.12.0-win-x64.zip"
$out = "$env:TEMP\node-v22.12.0-win-x64.zip"
Write-Host "Downloading Node.js 22..."
try {
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $out)
    Write-Host "Download complete."
} catch {
    Write-Host "Download failed: $($_.Exception.Message)"
    exit 1
}
Write-Host "Extracting..."
try {
    Expand-Archive -Path $out -DestinationPath "$env:TEMP\node-portable" -Force
    Write-Host "Extract complete."
} catch {
    Write-Host "Extract failed: $($_.Exception.Message)"
    exit 1
}
Write-Host "Done."