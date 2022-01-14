<#PSScriptInfo

.VERSION 1.0

.GUID 

.AUTHOR magoedte@microsoft.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES Based on the original version written by Doug Bradley (MSFT) for Azure Monitor VM Insights.

.PRIVATEDATA

#>

<#
.SYNOPSIS
This script installs VM extension for Log Analytics as needed for Azure Monitor, Azure Security Center, Azure Sentinel, and Azure Automation
Hybrid Runbook Worker role (either in support of Update Management and Change Tracking and Inventory, or runbooks) on a server
or virtual machine registered with Arc-enabled servers.

.DESCRIPTION
This script installs hybrid servers or virtual machines registered with Arc-enabled servers:
- Log Analytics VM extension configured to supplied Log Analytics workspace

Can be applied to:
- Subscription
- Resource Group in a Subscription
- Specific machine
- Compliance results of a policy for a machine

Script will show you list of machines that are applicable and let you confirm to continue.
Use -Approve switch to run without prompting, if all required parameters are provided.

If the extensions are already installed, re-installation will not be attempted.

Use -WhatIf if you would like to see what would happen in terms of installs, what workspace is configured, and status of the extension.

.PARAMETER WorkspaceId
Log Analytics workspaceID (GUID) for the data to be sent to

.PARAMETER WorkspaceKey
Log Analytics workspace primary or secondary key

.PARAMETER SubscriptionId
SubscriptionId hosting the services and target hybrid resources.
If using PolicyAssignmentName parameter, specify the subscription that Arc-enabled servers machine's are in.

.PARAMETER ResourceGroup
<Optional> Resource Group to which the Arc-enabled servers belong to

.PARAMETER Name
<Optional> To install to a single Arc-enabled server

.PARAMETER PolicyAssignmentName
<Optional> Take the input Arc-enabled server machines to operate on as the Compliance results from this Assignment
If specified will only take from this source.

.PARAMETER Approve
<Optional> Gives the approval for the installation to start with no confirmation prompt for the listed VM's/VM Scale Sets

.PARAMETER Whatif
<Optional> See what would happen in terms of installs.
If extension is already installed will show what workspace is currently configured, and status of the VM extension

.PARAMETER Confirm
<Optional> Confirm every action

.EXAMPLE
.\Install-LAExtension.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -ResourceGroup <ResourceGroup>
Install for all machines in a Resource Group in a subscription

.EXAMPLE
.\Install-LAExtension.ps1 -WorkspaceId <WorkspaceId> -WorkspaceKey <WorkspaceKey> -SubscriptionId <SubscriptionId> -PolicyAssignmentName a4f79f8ce891455198c08736
Specify to use a PolicyAssignmentName for source

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(mandatory = $true)][string]$workspaceId,
    [Parameter(mandatory = $true)][string]$workspaceKey,
    [Parameter(mandatory = $true)][string]$subscriptionId,
    [Parameter(mandatory = $false)][string]$resourceGroupName,
    [Parameter(mandatory = $false)][string]$name,
    [Parameter(mandatory = $false)][string]$policyAssignmentName,
    [Parameter(mandatory = $false)][switch]$approve
)


#
# FUNCTIONS
#
function Get-VMExtension {
    <#
	.SYNOPSIS
	Return the machine extension of specified ExtensionType
	#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)][string]$machineName,
        [Parameter(mandatory = $true)][string]$resourceGroupName,
        [Parameter(mandatory = $true)][string]$extensionType
    )

    $machine = Get-AzConnectedMachineExtension -MachineName $machineName -ResourceGroupName $resourceGroupName
    $extensions = $machine.Name
    Write-Output $extensionType

    foreach ($extension in $extensions) {
        if ($extensionType -eq $extension.Name) {
            Write-Verbose("$machineName : Extension: $extensionType found on machine")
            Write-Output $extension
            $extension
            return
        }
    }
    Write-Verbose("$machineName : Extension: $extensionType not found on machine")
}

function Install-VMExtension {
    <#
	.SYNOPSIS
	Install machine extension, handle if already installed
	#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)][string]$machineName,
        [Parameter(mandatory = $true)][string]$machineLocation,
        [Parameter(mandatory = $true)][string]$resourceGroupName,
        [Parameter(mandatory = $true)][string]$extensionType,
        [Parameter(mandatory = $true)][string]$ExtensionName,
        [Parameter(mandatory = $true)][string]$extensionPublisher,
        [Parameter(mandatory = $true)][string]$extensionVersion,
        [Parameter(mandatory = $false)][hashtable]$publicSettings,
        [Parameter(mandatory = $false)][hashtable]$protectedSettings,

        [Parameter(mandatory = $true)][hashtable]$onboardingStatus
    )
    # Use supplied name unless already deployed, use same name
    $extensionName = $ExtensionName

    $extension = Get-AzConnectedMachineExtension -machineName $machineName -resourceGroupName $resourceGroupname -Name $extensionName
    if ($extension.Name -eq $extensionName) {
           $message = "$machineName already has the extension " + $extensionType + " installed."
           Write-Output($message)
           $onboardingStatus.AlreadyOnboarded += $message
    }

    if ($PSCmdlet.ShouldProcess($machineName, "install extension $extensionType") -and (!$extension)) {

        $parameters = @{
            ResourceGroupName  = $resourceGroupName
            VMName             = $machineName
            Location           = $machineLocation
            Publisher          = $extensionPublisher
            ExtensionType      = $extensionType
            ExtensionName      = $extensionName
            TypeHandlerVersion = $extensionVersion
        }

        if ($publicSettings -and $protectedSettings) {
            $parameters.Add("Settings", $publicSettings)
            $parameters.Add("ProtectedSettings", $protectedSettings)
        }

        if ($extensionType -eq "OmsAgentForLinux") {
            Write-Output("$machineName : ExtensionType: $extensionType does not support updating workspace. Uninstalling and Re-Installing")
            $removeResult = Remove-AzConnectedMachineExtension -ResourceGroupName $resourceGroupName -MachineName $machineName -Name $extensionName -Force

            if ($removeResult -and $removeResult.IsSuccessStatusCode) {
                $message = "$machineName : Successfully removed $extensionType"
                Write-Output($message)
            }
            else {
                $message = "$machineName : Failed to remove $extensionType (for $extensionType need to remove)"
                Write-Warning($message)
                $onboardingStatus.Failed += $message
            }
        }

        Write-Output("$machineName : Deploying $extensionType with name $extensionName")
        $result = New-AzConnectedMachineExtension @parameters

        if ($result -and $result.IsSuccessStatusCode) {
            $message = "$machineName : Successfully deployed $extensionType"
            Write-Output($message)
            $onboardingStatus.Succeeded += $message
        }
        else {
            $message = "$machineName : Failed to deploy $extensionType"
            Write-Warning($message)
            $onboardingStatus.Failed += $message
        }
    }
}

#
# Main Script
#

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null

# Sign in to your Azure subscription
$subscription = Get-AzSubscription -ErrorAction SilentlyContinue
if(-not($subscription))
{
    Connect-AzAccount
}

$account = Get-AzContext

if ($null -eq $account.Account) {
    Write-Output("Account context not found, please login")
    Connect-AzAccount -subscriptionid $SubscriptionId
}
else {
    if ($account.Subscription.Id -eq $SubscriptionId) {
        Write-Verbose("Subscription: $SubscriptionId is already selected.")
        $account
    }
    else {
        Write-Output("Current Subscription:")
        $account
        Write-Output("Changing to subscription: $SubscriptionId")
        Set-AzContext -SubscriptionId $SubscriptionId
    }
}

$machines = @()

# To report on overall status
$AlreadyOnboarded = @()
$OnboardingSucceeded = @()
$OnboardingFailed = @()
$OnboardingBlockedNotRunning = @()
$OnboardingBlockedDifferentWorkspace = @()
$machineScaleSetNeedsUpdate = @()
$onboardingStatus = @{
    AlreadyOnboarded      = $AlreadyOnboarded;
    Succeeded             = $OnboardingSucceeded;
    Failed                = $OnboardingFailed;
    NotRunning            = $OnboardingBlockedNotRunning;
    DifferentWorkspace    = $OnboardingBlockedDifferentWorkspace;
}

# Log Analytics extension constants
$mmaExtensionMap = @{ "Windows" = "MicrosoftMonitoringAgent"; "Linux" = "OmsAgentForLinux" }
$mmaExtensionVersionMap = @{ "Windows" = "1.0"; "Linux" = "1.6" }
$mmaExtensionPublisher = "Microsoft.EnterpriseCloud.Monitoring"
$mmaExtensionName = "MMAExtension"
$publicSettings = @{"workspaceId" = $workspaceId; "stopOnMultipleConnections" = "true"}
$protectedSettings = @{"workspaceKey" = $workspaceKey}

if ($policyAssignmentName) {
    Write-Output("Getting list of machines from PolicyAssignmentName: " + $policyAssignmentName)
    $complianceResults = Get-AzPolicyState -PolicyAssignmentName $policyAssignmentName

    foreach ($result in $complianceResults) {
        Write-Verbose($result.ResourceId)
        Write-Verbose($result.ResourceType)
        if ($result.SubscriptionId -ne $subscriptionId) {
            Write-Output("Machine is not in same subscription, this scenario is not currently supported. Skipping this machine.")
        }

        $machineName = $result.ResourceId.split('/')[8]
        $machineResourceGroup = $result.ResourceId.split('/')[4]

        # Skip if ResourceGroup or Name provided, but does not match
        if ($resourceGroup -and $resourceGroup -ne $machineResourceGroup) { continue }
        if ($Name -and $Name -ne $machineName) { continue }

        $machine = Get-AzConnectedMachine -Name $machineName -ResourceGroupName $machineResourceGroup
        $machineStatus = $machine.Status

        $machines = @($machine)
    }
}

if (! $policyAssignmentName) {
    Write-Output("Getting list of machines matching criteria specified")
    if (!$resourceGroupName -and !$name) {
        # If ResourceGroupName value is not passed - get all machines under given SubscriptionId
        $machines = Get-AzConnectedMachine -SubscriptionId $subscriptionId
    }
    else {
        # If ResourceGroupName value is passed - select all machines under given ResourceGroup
        $machines = Get-AzConnectedMachine -ResourceGroupName $resourceGroupName
        if ($Name) {
            $machines = $machine | Where-Object {$_.Name -like $Name}
        }
    }
}

Write-Output("`nMachines matching criteria:`n")
$machines | ForEach-Object { Write-Output ($_.Name + " " + $_.Status) }

# Validate customer wants to continue
Write-Output("`nThis operation will attempt to install the Log Analytics extension on $($machines.Count) machines listed above.")
Write-Output("Machines in a non-running state will be skipped.")
Write-Output("Extension will not be re-installed if already installed.")
if ($approve -eq $true -or !$PSCmdlet.ShouldProcess("All") -or $PSCmdlet.ShouldContinue("Continue?", "")) {
    Write-Output ""
}
else {
    Write-Output "You selected No - exiting"
    return
}

#
# Loop through each machine, as appropriate handle installing VM Extensions
#
Foreach ($machine in $machines) {
    # set as variabels so easier to use in output strings
    $machineName = $machine.Name
    $machineLocation = $machine.Location

    # If script scoped machines by subscrption, we need to get the resource
    # group in order to query if it has the VM extension installed and to install the VM extension.
    If (!$resourceGroupName) {
        $resourceGroupName = (Get-AzResource -ResourceType Microsoft.HybridCompute/machines -Name $machineName).ResourceGroupName
    }
    
    #
    # Find OS Type
    #
    $osType = $machine.OSName

    #
    # Map to correct extension for OS type
    #
    $mmaExt = $mmaExtensionMap.($osType.ToString())
    if (! $mmaExt) {
        Write-Warning("$machineName : has an unsupported OS: $osType")
        continue
    }
    $mmaExtVersion = $mmaExtensionVersionMap.($osType.ToString())

    Write-Verbose("Deployment settings: ")
    Write-Verbose("ResourceGroup: $resourceGroupName")
    Write-Verbose("Machine: $machineName")
    Write-Verbose("Location: $machineLocation")
    Write-Verbose("OS Type: $ext")
    Write-Verbose("Monitoring Agent: $mmaExt, HandlerVersion: $mmaExtVersion")

    #
    # Handle machines
    #
    
    if ("Connected" -ne $machine.Status) {
		$message = "$machineName is not connected. Reported state is: " + $machine.Status + " --Skipping"
		Write-Output($message)
		$onboardingStatus.NotRunning += $message
		continue
        }

        $message = "$machineName is connected, continuing with operation."
        Write-Output($message)

        $publicSetting = @{"workspaceId" = $workspaceId }
        $protectedSetting = @{"workspaceKey" = $workspaceKey }

        Install-VMExtension `
            -machineName $machineName `
            -machineLocation $machineLocation `
            -resourceGroupName $resourceGroupName `
            -ExtensionType $mmaExt `
            -ExtensionName $mmaExtensionName `
            -ExtensionPublisher $mmaExtensionPublisher `
            -ExtensionVersion $mmaExtVersion `
            -PublicSettings $publicSettings `
            -ProtectedSettings $protectedSettings `
            -OnboardingStatus $onboardingStatus

        Write-Output("`n")
}

Write-Output("`nSummary:")
Write-Output("`nAlready Onboarded: (" + $onboardingStatus.AlreadyOnboarded.Count + ")")
$onboardingStatus.AlreadyOnboarded  | ForEach-Object { Write-Output ($_) }
Write-Output("`nSucceeded: (" + $onboardingStatus.Succeeded.Count + ")")
$onboardingStatus.Succeeded | ForEach-Object { Write-Output ($_) }
Write-Output("`nConnected to different workspace: (" + $onboardingStatus.DifferentWorkspace.Count + ")")
$onboardingStatus.DifferentWorkspace | ForEach-Object { Write-Output ($_) }
Write-Output("`nNot running - start machine to configure: (" + $onboardingStatus.NotRunning.Count + ")")
$onboardingStatus.NotRunning  | ForEach-Object { Write-Output ($_) }
Write-Output("`nFailed: (" + $onboardingStatus.Failed.Count + ")")
$onboardingStatus.Failed | ForEach-Object { Write-Output ($_) }