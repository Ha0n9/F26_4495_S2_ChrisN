# Module loader.
#
# Every .ps1 under Public and Private is dot sourced, then only the Public
# names are exported. Splitting one function per file keeps each check
# reviewable on its own and keeps this loader from ever needing to change
# when a check is added.

$public  = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1"          -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1"         -ErrorAction SilentlyContinue)
$checks  = @(Get-ChildItem -Path "$PSScriptRoot\Private\Checks\*.ps1"  -ErrorAction SilentlyContinue)

foreach ($file in @($private + $checks + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load $($file.Name): $_"
    }
}

Export-ModuleMember -Function $public.BaseName
