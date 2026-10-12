@{
    RootModule        = 'ADSecurityAudit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '8f2c4a16-5b3d-4e97-9c81-2a6d7f0e4b35'
    Author            = 'Chris Nghiem'
    Description       = 'Scans an Active Directory domain for common security misconfigurations and writes the results as structured JSON.'

    # 5.1 is the version shipped with Windows Server, so the module has to run
    # there as well as on PowerShell 7.
    PowerShellVersion = '5.1'

    # RSAT. Listed rather than imported blindly so the failure is a clear
    # message about a missing prerequisite instead of a cmdlet-not-found error.
    RequiredModules   = @('ActiveDirectory')

    FunctionsToExport = @('Invoke-ADSecurityAudit')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('ActiveDirectory', 'Security', 'Audit', 'BlueTeam')
            ProjectUri = 'https://github.com/Ha0n9/F26_4495_S2_ChrisN'
        }
    }
}
