# Server Organisms - one-command install (Windows). Data stays on your server.
$ErrorActionPreference = "Stop"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker required: https://docs.docker.com/get-docker/" }
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
function New-Token { $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $b = New-Object byte[] 32; $rng.GetBytes($b); -join ($b | ForEach-Object { $_.ToString("x2") }) }
function Ensure-Token($name) {
  if (-not (Select-String -Path .env -Pattern "^$name=.+" -Quiet)) {
    $v = New-Token
    if (Select-String -Path .env -Pattern "^$name=" -Quiet) { (Get-Content .env) -replace "^$name=.*", "$name=$v" | Set-Content .env } else { Add-Content .env "$name=$v" }
    Write-Host "Generated private $name in .env (keep secret)"
  }
}
Ensure-Token "BROKER_TOKEN"
Ensure-Token "GATEWAY_TOKEN"
Ensure-Token "AUDIT_TOKEN"
Ensure-Token "IDENTITY_HMAC_KEY"
docker compose up --build -d
$tok = (Get-Content .env | Where-Object { $_ -match "^BROKER_TOKEN=" }) -replace "^BROKER_TOKEN=", ""
$gtok = (Get-Content .env | Where-Object { $_ -match "^GATEWAY_TOKEN=" }) -replace "^GATEWAY_TOKEN=", ""
Write-Host ""
Write-Host "OPEN YOUR DASHBOARD (private link - do not share): http://127.0.0.1:18000/#token=$tok&gwtoken=$gtok"
Write-Host "Gateway (put your API behind it): http://127.0.0.1:18010"
