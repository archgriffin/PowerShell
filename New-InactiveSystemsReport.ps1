<#
	.SYNOPSIS
	Gather information from Active Directory to generate a report and run 
	actions against Computer Accounts that have aged out in order to keep
	Active Directory clean.
	
	.DESCRIPTION
	Using the LastPasswordChanged field along with other information gathered
	from Active Directory, the script will Move aged computers to a specified OU,
	Disable computer accounts sitting in this speicifc OU at a certain Age, and 
	Delete Computer accounts that have remained Disabled in the OU for a specified
	amount of time. 

	Disabling of computer accounts happens after the Deletion phase, this is to 
	ensure that accounts that just got disabled, do not also get deleted at the same time.

    The HoldingOU Parameter actually uses the Get-ADOrganizationalUnit with a filter to 
    attempt to find the OU you are requesting so that you do not have to type in the full 
    Distinguished Name of the Organizational Unit you want machines to be moved to. Also 
    without the HoldingOU parameter the script may not properly process machines that need 
    to be disabled or deleted. 

	.EXAMPLE
	PS > New-InactiveSystemsReport.ps1 -HoldingOU "OldComputers" -IgnoreComputerName "*VirtDesktop*","vDesktop*","vmaster" -IgnoreComputerDescription "*DO NOT DISABLE*" -OutFilePath "c:\temp\inactivecomputersreport.html"
	Using the default parameters for age restraints, will move all computers with a PasswordLastSet age of 45 days to 
	an OU called OldComputers. It will ignore computers with the texts 'VirtDesktop', 'vdekstop', and 'vmaster'
	in the computer name, and it will also ignore computers with the text 'do not disable' within the 
	description fields. This will generate the report html file at c:\temp\inactivecomputersreport.html

	.EXAMPLE
	PS > New-InactiveSystemsReport.ps1 -HoldingOU "OldComputers" -OutFilePath "c:\temp\inactivecomputersreport.html" -DoNotMove -DoNotDisable -DoNotDelete -SendEmail -SMTPServer my-smtp -EmailRecpients "ServerTeam <help@systems.com>"
	Generates a report that is saved at "c:\temp\inactivecomputersreport.html", and is also emailed
	to the Server Support team.

	.INPUTS
	System.String,System.DateTime,System.Boolean

	.OUTPUTS
	None.

	.NOTES
	===========================================================================
	 Created on:   	2013-09-13
	 Created by:   	Raymond Slieff <raymond@slieff.net>
	 Filename:     	New-InactiveSystemsReport.ps1
	===========================================================================
	.Link
	None.
	#Requires -Version 3
	#Requires -Modules ActiveDirectory
#>

#region GIT Information
# 
# More regioning for code readability
#
#endregion GIT Information

#region Parameters
[CmdletBinding()]
Param
(
	# Machines older than this date will be included on the report
	[Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[datetime] $ReportDate = (get-date).AddDays(-45),
	# Machines older than this date will be moved to the Holding OU
	[Parameter(Mandatory = $false, Position = 1, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[datetime] $MoveDate = (get-date).AddDays(-60),
	# Machines older than this date will be disabled if within the proper Holding OU
	[Parameter(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[datetime] $DisableDate = (get-date).AddDays(-75),
	# Machines older than this date, previously disabled, and in the Holding OU will be removed
	[Parameter(Mandatory = $false, Position = 3, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[datetime] $RemoveDate = (get-date).AddDays(-90),
	# Name of OU to place machines in to older than the MoveDate, will be found with Get-ADOrganizationUnit -Filter {name -eq $HoldingOU}
	[Parameter(Mandatory = $false, Position = 4, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[string] $HoldingOU = $null,
	# Text that will be used to exclude computers by name from the 'To be reviewed' portion of the report.
	[Parameter(Mandatory = $false, Position = 5, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[string[]] $IgnoreComputerName = '',
	# Text that will be used to exclude computers by description from the 'To be reviewed' portion of the report.
	[Parameter(Mandatory = $false, Position = 6, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[string[]] $IgnoreComputerDescription = '',
	# The output path of the HTML report document
	[Parameter(Mandatory = $false, Position = 7, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[string] $OutFilePath = $null,
	# If the report should be sent out as an email
	[Parameter(Mandatory = $false, Position = 8, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Email Param Set")]
	[switch] $SendEmail,
	# Used with $SendEmail, determines the SMTP server to use for relaying the email message
	[Parameter(Mandatory = $true, Position = 9, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Email Param Set")]
	[string] $SMTPServer,
	# Sets the EMail Subject line
	[Parameter(Mandatory = $false, Position = 10, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Email Param Set")]
	[string] $EmailSubject = "Inactive Computer Report",
	# List of Email Recpients in the form of NAME <email@address.net>
	[Parameter(Mandatory = $true, Position = 11, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Email Param Set")]
	[string[]] $EmailRecpients,
	# Sets the Sender information for the email in the form of NAME <email@address.net>
	[Parameter(Mandatory = $false, Position = 12, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Email Param Set")]
	[string] $EmailSender = "Do Not Reply <donotreply@nodomain.local>",
	# Will not move the machines to the Active Directory specified holding OU, but will include them on the report.
	[Parameter(Mandatory = $false, Position = 13, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[switch] $DoNotMove = $false,
	# Will not disable machines in Active Directory, but will include them on the report.
	[Parameter(Mandatory = $false, Position = 14, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[switch] $DoNotDisable = $false,
	# Will not delete machines from Active Directory, but will include them on the report.
	[Parameter(Mandatory = $false, Position = 15, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Default Param Set")]
	[Parameter(ParameterSetName = "Email Param Set")]
	[switch] $DoNotDelete = $false
)

#endregion Parameters

#region Script Level Functions
<#
	.Synopsis
		Checks to see if a PowerShell module is already loaded
		or not. If the module is not loaded, but exists, it will
		attempt to load the module. If the module does not exist
		then we need to exit the script because there are dependancies
		that must be met through the module.
	
	.DESCRIPTION
		Checks to see if a PowerShell module is already loaded
		or not. If the module is not loaded, but exists, it will
		attempt to load the module. If the module does not exist
		then we need to exit the script because there are dependancies
		that must be met through the module.
	
	.PARAMETER ModuleName
		Name of the module to check for and import in available. 
	
	.EXAMPLE
				PS C:\> Get-RequiredModule -ModuleName 'Value1'
	
	.NOTES
		AUTHOR: Raymond Slieff <raymond@slieff.net>
		Create : 2014.05.02
		LASTEDIT: 2014.05.21
#>
function Get-RequiredModule
{
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   Position = 1)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ModuleName
	)
	
	if (-not (Get-Module -name $ModuleName))
	{
		if (Get-Module -ListAvailable -Name $ModuleName)
		{
			Write-Verbose -Message "Module `'$ModuleName`' will be imported."
			Import-Module -Name $ModuleName -Verbose:$false
			Return $true
		}
		else
		{
			Write-Verbose -Message "Module `'$ModuleName`' is not available."
			Return $false
		} # if Module Available
	}
	else
	{
		Write-Verbose -Message "Module `'$ModuleName`' is already loaded."
		Return $true
	} # if Module loaded
} # Get-RequiredModule

function Sort-ComputerAccounts ($InputComputerArray, $ComputerNameFilter, $ComputerDescriptionFilter)
{
	$OuputReviewArray = @()
	$OutputIgnoreArray = @()
	foreach ($pc in $InputComputerArray)
	{
		Write-Verbose -Message "Comparing name against Ignored Computer List array."
		foreach ($FilteredPCName in $ComputerNameFilter)
		{
			if ($pc.Name -like $FilteredPCName)
			{
				$Review = $false
				break
			}
			else
			{
				$Review = $true
				foreach ($FilteredDescription in $ComputerDescriptionFilter)
				{
					if ($pc.Description -like $FilteredDescription)
					{
						$Review = $false
						break
					} # if description like $FilteredDescription
				} # foreach Description Filter
			} # if Name in Name Filter
		} # foreach computer name ignore
		if ($Review)
		{
			Write-Verbose -Message "$($pc.Name) added to the list of computer accounts to review."
			$OuputReviewArray += $pc
		}
		else
		{
			Write-Verbose -Message "$($pc.Name) added to the list of computer accounts to ignore."
			$OutputIgnoreArray += $pc
		} # if $Review
	} # foreach PCs in Array
	return @($OuputReviewArray, $OutputIgnoreArray)
} # Sort-ComputerAccounts

<#
	.SYNOPSIS
		Based on Parameter set, take an array of computer accounts, and within Active Directory either move them to a specified OU, disable them, or delete them. 
	
	.DESCRIPTION
		Takes the InputComputerArray as an array of AD Computer accounts and compares the PasswordLastSet date against the given CompareDate. Then if the Move parameter is given, and the PasswordLastSet date is older than the CompareDate will move accounts to a predetermined Organizational Unit, If the Disable switch is given and the PasswordLastSet date is older than the CompareDate it will disable the computer. If the Delete switch is used and the PasswordLastSet date is older than the CompareDate it will delete the machine from Active Directory. 
		
		The ActionFlag may be used with the Delete, Disable, and Move parameters to just create the report. If it is set to $true it the parameter action will actually be carried out. If it is set to $false, it will just create the report without actually performing any of the actions. 
	
	.PARAMETER InputComputerArray
		A description of the InputComputerArray parameter.
	
	.PARAMETER CompareDate
		A description of the CompareDate parameter.
	
	.PARAMETER Delete
		A description of the Delete parameter.
	
	.PARAMETER Disable
		A description of the Disable parameter.
	
	.PARAMETER Move
		A description of the Move parameter.
	
	.PARAMETER ActionFlag
		A description of the ActionFlag parameter.
	
	.EXAMPLE
				PS C:\> Process-ComputerAccounts -InputComputerArray $value1 -CompareDate $value2
	
	.NOTES
		Additional information about the function.
#>
function Process-ComputerAccounts
{
	[CmdletBinding(DefaultParameterSetName = 'DeleteAccount')]
	param
	(
		[Parameter(Mandatory = $true,
				   Position = 0)]
		[Parameter(ParameterSetName = 'DeleteAccount',
				   Position = 0)]
		[Parameter(ParameterSetName = 'DisableAccount',
				   Position = 0)]
		[Parameter(ParameterSetName = 'MoveAccount',
				   Position = 0)]
		[array]
		$InputComputerArray = @(),
		[Parameter(ParameterSetName = 'DeleteAccount')]
		[Parameter(ParameterSetName = 'DisableAccount')]
		[Parameter(ParameterSetName = 'MoveAccount')]
		[datetime]
		$CompareDate,
		[Parameter(ParameterSetName = 'DeleteAccount')]
		[switch]
		$Delete = $false,
		[Parameter(ParameterSetName = 'DisableAccount')]
		[switch]
		$Disable = $false,
		[Parameter(ParameterSetName = 'MoveAccount')]
		[switch]
		$Move = $false,
		[Parameter(ParameterSetName = 'DeleteAccount')]
		[Parameter(ParameterSetName = 'DisableAccount')]
		[Parameter(ParameterSetName = 'MoveAccount')]
		[boolean]
		$ActionFlag = $true
	)
	
	$ReturnArray = @()
	
	if ($InputComputerArray[0] -ne "IHAVENOCOMPUTERS")
	{
		foreach ($pc in $InputComputerArray)
		{
			if ($pc.PasswordLastSet -lt $CompareDate)
			{
				if ($Delete)
				{
					if ((Get-ADComputer $pc.Name).enabled -eq $false)
					{
						Write-Verbose -Message "$($pc.Name) should be Removed from Active Directory."
						$ReturnArray += $pc
						if ($ActionFlag -eq $false)
						{
							Get-ADComputer $pc.name | Remove-ADComputer -Confirm:$false
						} # if $ActionFlag switch
					}
					else
					{
						Write-Verbose -Message "$($pc.Name) should be Removed from Active Directory, but has not previously been disabled, so it will not be deleted."
					} # if account is not disabled
				} # if Delete switch
				
				if ($Disable)
				{
					if ((Get-ADComputer $pc.Name).enabled -eq $true)
					{
						Write-Verbose -Message "$($pc.Name) should be Disabled."
						$ReturnArray += $pc
						if ($ActionFlag -eq $false)
						{
							Get-ADComputer $pc.name | Set-ADComputer -Enabled:$false -Confirm:$false
						} # if $ActionFlag switch
					}
					else
					{
						Write-Verbose -Message "$($pc.Name) should be Disabled in Active Directory, but has previously been disabled, so it will not be disabled again."
					} # if account is disabled
				} # if Disable switch
				
				if ($Move)
				{
					Write-Verbose -Message "$($pc.Name) should be moved to $HoldingOU"
					$ReturnArray += $pc
					if ($ActionFlag -eq $false)
					{
						Get-ADComputer $pc.name | Move-ADObject -TargetPath $HoldingOUObject -Confirm:$false
					} # if $ActionFlag
				} # if $Move
			} # if $CompareDate
		} # foreach IsolatedWindowsComputers
		
		return $ReturnArray
	}
	else
	{
		return $ReturnArray = @()
	} # if $InputComputerArray
} # Process-ComputerAccounts

Get-RequiredModule -ModuleName ActiveDirectory | Out-Null

#endregion Script Level Functions

#region Nullify Variables
$WindowsComputers = $null
$NonWindowsComputers = $null
$WindowsComputersToReview = $null
$NonWindowsComputersToReview = $null
$WindowsComputersToMove = $null
$NonWindowsComputersToMove = $null
$WindowsComputersToDisable = $null
$NonWindowsComputersToDisable = $null
$WindowsComputersToDelete = $null
$NonWindowsComputersToDelete = $null
#endregion Nullify Variables

#region Find Holding OU in Active Directory
if ($HoldingOU -ne $null)
{
	$HoldingOUObject = Get-ADOrganizationalUnit -Filter { name -like $HoldingOU }
	$OUObjectCount = $HoldingOUObject | Measure-Object
	if ($OUObjectCount.Count -ne 1)
	{
		Write-Error -Message "More than one OU Object was returned finding $HoldingOU, cannot continue."
		return $false
	} # if $OUObjectCount
} # if $HoldingOU
#endregion Find Holding OU in Active Directory

#region Populate from Active Directory
Write-Verbose -Message "Creating computer lists from Active Directory."
Write-Verbose -Message "Scanning Active Directory for computer accounts labelled as Windows machines."
$WindowsComputers = Get-ADComputer -ResultSetSize $null -Properties Description,PasswordLastSet,ManagedBy,WhenChanged,WhenCreated,OperatingSystem -Filter {(PasswordLastSet -lt $ReportDate) -and (OperatingSystem -like "*Windows*")} |
	Select-Object Name, @{ Label = "DaysInactive"; Expression = { ((Get-Date) - $_.PasswordLastSet).Days } }, @{ Label = "LastLoggedOnUser"; Expression = { (Get-ADUser ($_.ManagedBy)).Name } }, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem, DistinguishedName |
	Sort-Object Name
Write-Verbose -Message "Found $($WindowsComputers.Count) computer accounts identified as Windows OS."

Write-Verbose -Message "Scanning Active Directory for computer accounts not labelled as Windows machines."
$NonWindowsComputers = Get-ADComputer -ResultSetSize $null -Properties Description,PasswordLastSet,ManagedBy,WhenChanged,WhenCreated,OperatingSystem -Filter {(PasswordLastSet -lt $ReportDate)} | 
    Where-Object {($_.OperatingSystem -notlike "*windows*") -or ($_.OperatingSystem -eq $null)} |
	Select-Object Name, @{ Label = "DaysInactive"; Expression = { ((Get-Date) - $_.PasswordLastSet).Days } }, Description, PasswordLastSet, WhenChanged, WhenCreated, DistinguishedName | 
    Sort-Object Name
Write-Verbose -Message "Found $($NonWindowsComputers.Count) computer accounts identified as non-Windows OS computer accounts."
#endregion Populate from Active Directory

#region Process Active Directory Results
$WindowsComputersToReview = @()
$WindowsComputersToIgnore = @()
Write-Verbose -Message "Beginning the processing of Windows identified computers."
$parms = @{
	'InputComputerArray' = $WindowsComputers;
	'ComputerNameFilter' = $IgnoreComputerName;
	'ComputerDescriptionFilter' = $IgnoreComputerDescription
}
($WindowsComputersToReview, $WindowsComputersToIgnore) = Sort-ComputerAccounts @parms

$NonWindowsComputersToReview = @()
$NonWindowsComputersToIgnore = @()
Write-Verbose -Message "Beginning the processing of non-Windows identified computers."
$parms = @{
	'InputComputerArray' = $NonWindowsComputers;
	'ComputerNameFilter' = $IgnoreComputerName;
	'ComputerDescriptionFilter' = $IgnoreComputerDescription
}
($NonWindowsComputersToReview, $NonWindowsComputersToIgnore) = Sort-ComputerAccounts @parms
#endregion Process Active Directory Results

#region Process Holding OU machines
$IsolatedWindowsComputers = $WindowsComputersToReview |
	Where-Object { $_.DistinguishedName -like "*$HoldingOU*" }
$IsolatedNonWindowsComputers = $NonWindowsComputersToReview |
	Where-Object { $_.DistinguishedName -like "*$HoldingOU*" }
$WindowsComputersToReview = $WindowsComputersToReview |
	Where-Object { $_.DistinguishedName -notlike "*$HoldingOU*" }
$NonWindowsComputersToReview = $NonWindowsComputersToReview |
Where-Object { $_.DistinguishedName -notlike "*$HoldingOU*" }
#endregion Process Holding OU machines

#region Check for Empty Variables
if ($IsolatedWindowsComputers -eq $null)
{
	$IsolatedWindowsComputers = @("IHAVENOCOMPUTERS")
} # if $IsolatedWindowsComputers
if ($IsolatedNonWindowsComputers -eq $null)
{
	$IsolatedNonWindowsComputers = @("IHAVENOCOMPUTERS")
} # if $IsolatedNonWindowsComputers
if ($WindowsComputersToReview -eq $null)
{
	$WindowsComputersToReview = @("IHAVENOCOMPUTERS")
} # if $WindowsComputersToReview
if ($NonWindowsComputersToReview -eq $null)
{
	$NonWindowsComputersToReview = @("IHAVENOCOMPUTERS")
} # if $NonWindowsComputersToReview
#endregion Check for Empty Variables

#region REMOVE COMPUTER ACCOUNTS
$WindowsComputersToDelete = @()
$NonWindowsComputersToDelete = @()
$parms = @{
	'InputComputerArray' = $IsolatedWindowsComputers;
	'CompareDate' = $RemoveDate;
	'ActionFlag' = $DoNotDelete;
	'Delete' = $true;
	'ErrorAction' = 'SilentlyContinue';
	'ErrorVariable' = 'ErrorDump'
}
[array]$WindowsComputersToDelete = Process-ComputerAccounts @parms
$parms = @{
	'InputComputerArray' = $IsolatedNonWindowsComputers;
	'CompareDate' = $RemoveDate;
	'ActionFlag' = $DoNotDelete;
	'Delete' = $true;
	'ErrorAction' = 'SilentlyContinue';
	'ErrorVariable' = 'ErrorDump'
}
[array]$NonWindowsComputersToDelete = Process-ComputerAccounts @parms
#endregion REMOVE COMPUTER ACCOUNTS

#region DISABLE COMPUTER ACOUNTS
$WindowsComputersToDisable = @()
$NonWindowsComputersToDisable = @()
$parms = @{
	'InputComputerArray' = $IsolatedWindowsComputers;
	'CompareDate' = $DisableDate;
	'ActionFlag' = $DoNotDisable;
	'Disable' = $true;
	'ErrorAction' = 'SilentlyContinue';
	'ErrorVariable' = 'ErrorDump'
}
[array]$WindowsComputersToDisable = Process-ComputerAccounts @parms
$parms = @{
	'InputComputerArray' = $IsolatedNonWindowsComputers;
	'CompareDate' = $DisableDate;
	'ActionFlag' = $DoNotDisable;
	'Disable' = $true;
	'ErrorAction' = 'SilentlyContinue';
	'ErrorVariable' = 'ErrorDump'
}
[array]$NonWindowsComputersToDisable = Process-ComputerAccounts @parms
#endregion DISABLE COMPUTER ACOUNTS

#region MOVE COMPUTER ACCOUNT TO TEMPOU
$WindowsComputersToMove = @()
$NonWindowsComputersToMove = @()
if ([bool](Get-ADOrganizationalUnit -Filter { name -eq $HoldingOU }))
{
	$parms = @{
		'InputComputerArray' = $WindowsComputersToReview;
		'CompareDate' = $MoveDate;
		'ActionFlag' = $DoNotMove;
		'Move' = $true;
		'ErrorAction' = 'SilentlyContinue';
		'ErrorVariable' = 'ErrorDump'
	}
	[array]$WindowsComputersToMove = Process-ComputerAccounts @parms
	$parms = @{
		'InputComputerArray' = $NonWindowsComputersToReview;
		'CompareDate' = $MoveDate;
		'ActionFlag' = $DoNotMove
		'Move' = $true;
		'ErrorAction' = 'SilentlyContinue';
		'ErrorVariable' = 'ErrorDump'
	}
	[array]$NonWindowsComputersToMove = Process-ComputerAccounts @parms
}
else
{
	Write-Error -Message "Cannot move Computer Accounts without specifying the HoldingOU when called, exiting script."
	return $false | Out-Null
} # if $HoldingOU can be found
#endregion MOVE COMPUTER ACCOUNT TO TEMPOU

#region Calculate Totals
$TotalADComputerAccounts = (Get-ADComputer -Filter * -ResultSetSize $null).Count
$TotalADWindowsComputerAccounts = (Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } -ResultSetSize $null).Count
$TotalADNonWindowsComputerAccounts = $TotalADComputerAccounts - $TotalADWindowsComputerAccounts

$TotalComputersToReview = $WindowsComputersToReview.Count + $NonWindowsComputersToReview.Count
$TotalComputersToIgnore = $WindowsComputersToIgnore.Count + $NonWindowsComputersToIgnore.Count
$TotalComputersMoved = $WindowsComputersToMove.Count + $NonWindowsComputersToMove.Count
$TotalComputersDisabled = $WindowsComputersToDisable.Count + $NonWindowsComputersToDisable.Count
$TotalComputersDeleted = $WindowsComputersToDelete.Count + $NonWindowsComputersToDelete.Count
#endregion Calculate Totals

#region TopLevelSummary HTML
$TopLevelSummary = @"
<h2>Summary</h2>
<table id='summary_table'>
  <tr>
    <th></th>
    <th>Windows</th>
	<th>Non-Windows</th>
	<th>Total</th>
  </tr>
  <tr>
    <th class='summary_table_hcolum'>Computer Accounts</th>
    <td>$TotalADWindowsComputerAccounts</td>
    <td>$TotalADNonWindowsComputerAccounts</td>
    <td>$TotalADComputerAccounts</td>
  </tr>
  <tr>
    <th class='summary_table_hcolum'>To Review</th>
    <td><a href="#WindowsComputersToReview">$($WindowsComputersToReview.Count)</a></td>
    <td><a href="#NonWindowsComputersToReview">$($NonWindowsComputersToReview.Count)</a></td>
    <td>$TotalComputersToReview</td>
  </tr>
  <tr>
    <th class='summary_table_hcolum'>To Ignore</th>
    <td><a href="#WindowsComputersToIgnore">$($WindowsComputersToIgnore.Count)</a></td>
    <td><a href="#NonWindowsComputersToIgnore">$($NonWindowsComputersToIgnore.Count)</a></td>
    <td>$TotalComputersToIgnore</td>
  </tr>
  <tr>
    <th class='summary_table_hcolum'>Moved</th>
    <td><a href="#WindowsComputersToMove">$($WindowsComputersToMove.Count)</a></td>
    <td><a href="#NonWindowsComputersToMove">$($NonWindowsComputersToMove.Count)</a></td>
    <td>$TotalComputersMoved</td>
  </tr>
  <tr>
    <th class='summary_table_hcolum'>Disabled</th>
    <td><a href="#WindowsComputersToDisable">$($WindowsComputersToDisable.Count)</a></td>
    <td><a href="#NonWindowsComputersToDisable">$($NonWindowsComputersToDisable.Count)</a></td>
    <td>$TotalComputersDisabled</td>
  </tr>
  <tr>
    <th class='summary_table_hcolum'>Deleted</th>
    <td><a href="#WindowsComputersToDelete">$($WindowsComputersToDelete.Count)</a></td>
    <td><a href="#NonWindowsComputersToDelete">$($NonWindowsComputersToDelete.Count)</a></td>
    <td>$TotalComputersDeleted</td>
  </tr>
</table>
"@
#endregion TopLevelSummary HTML

#region Create HTML Report
Write-Verbose -Message "Building HTML report"
Write-Verbose -Message "Processing Windows Computers to Review and converting data to HTML content."
$HTMLToReview = $WindowsComputersToReview |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
    ConvertTo-Html -Fragment -PreContent ("<a name='WindowsComputersToReview'><h2>" + $WindowsComputersToReview.Count + " Computers to Review</h2></a>")
Write-Verbose -Message "Processing Windows Computers to Ignore and converting data to HTML content." 
$HTMLToIgnore = $WindowsComputersToIgnore |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='WindowsComputersToIgnore'><h2>" + $WindowsComputersToIgnore.Count + " Computers to Ignore</a></h2>")
Write-Verbose -Message "Processing Non-Windows Computers to Review and converting data to HTML content."
$HTMLNonWindowsToReview = $NonWindowsComputersToReview |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
    ConvertTo-Html -Fragment -PreContent ("<a name='NonWindowsComputersToReview'><h2>" + $NonWindowsComputersToReview.Count + " Non-Windows Compters to Review</a></h2>")
Write-Verbose -Message "Processing Non-Windows Computers to Ignore and converting data to HTML content."
$HTMLNonWindowsComputersToIgnore = $NonWindowsComputersToIgnore |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='NonWindowsComputersToIgnore'><h2>" + $NonWindowsComputersToIgnore.Count + " Non-Windows Computers to Ignore</a></h2>")
Write-Verbose -Message "Processing Windows Computers to Move and converting data to HTML content."
$HTMLWindowsComputersToMove = $WindowsComputersToMove |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem | 
	ConvertTo-Html -Fragment -PreContent ("<a name='WindowsComputersToMove'><h2>$($WindowsComputersToMove.Count) Windows Computers to Move to $HoldingOU</a></h2>")
Write-Verbose -Message "Processing Non-Windows Computers to Move and converting data to HTML content."
$HTMLNonWindowsComputersToMove = $NonWindowsComputersToMove |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='NonWindowsComputersToMove'><h2>$($NonWindowsComputersToMove.Count) Non-Windows Computers to Move to $HoldingOU</a></h2>")
Write-Verbose -Message "Processing Windows Computers to Disable and converting data to HTML content."
$HTMLWindowsComputersToDisable = $WindowsComputersToDisable |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='WindowsComputersToDisable'><h2>$($WindowsComputersToDisable.Count) Windows Computers to Disable</a></h2>")
Write-Verbose -Message "Processing Non-Windows Computers to Disable and converting data to HTML content."
$HTMLNonWindowsComputersToDisable = $NonWindowsComputersToDisable |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='NonWindowsComputersToDisable'><h2>$($NonWindowsComputersToDisable.Count) Non-Windows Computers to Disable</a></h2>")
Write-Verbose -Message "Processing Windows Computers to Delete and converting data to HTML content."
$HTMLWindowsComputersToDelete = $WindowsComputersToDelete |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='WindowsComputersToDelete'><h2>$($WindowsComputersToDelete.Count) Windows Computers to Delete</a></h2>")
Write-Verbose -Message "Processing Non-Windows Computers to Delete and converting data to HTML content."
$HTMLNonWindowsComputersToDelete = $NonWindowsComputersToDelete |
	Select-Object Name, DaysInactive, LastLoggedOnUser, Description, PasswordLastSet, WhenChanged, WhenCreated, OperatingSystem |
	ConvertTo-Html -Fragment -PreContent ("<a name='NonWindowsComputersToDelete'><h2>$($NonWindowsComputersToDelete.Count) Non-Windows Computers to Delete</a></h2>")
#endregion Create HTML Report

#region HTML Header
Write-Verbose -Message "Creating HTML Header."
$HTMLhead = @"
<!DOCTYPE HTML>
<html>
    <head>
        <title>Inactive Computer Report</title>
    <style>
        body
        {
            background-color:#FAFAFA;
            font-family:Arial;
            font-size:12pt; 
        }
        td, th 
        { 
            border:1px solid black;
            border-collapse:collapse; 
        }
        th 
        { 
            color:white;
            background-color:black; 
        }
        table, tr, td, th 
        {
            padding: 2px; 
            margin: 0px 
        }
        tr:nth-child(odd) 
        {
            background-color: lightgray
        }
        table 
        {
            margin-left:10%;
            width:80%
        }
        img
        {
        float:left;
        margin: 0px 25px;
        }
        #footer
        {
            display:block;
            width:100%;
            text-align:center;
        }
        h2
        {
            text-align:center;
        }
		#summary_table
		{
			width:30%;
			margin-left:33%;
		}
		#summary_table td
		{
			text-align:right;
		}
		.summary_table_hcolum
		{
			text-align:right;
		}
    </style>
</head>
<body>
"@
#endregion HTML Header

#region HTML Footer
Write-Verbose -Message "Creating HTML Footer"
$HTMLFooter = @"
<div id='footer'>
    <i>$(get-date)</i>
</div>
</body>
</html>
"@
#endregion HTML Footer

#region Write HTML File
Write-Verbose -Message "Combining HTML Code fragments for the HTML body..."
$HTMLCode = $TopLevelSummary + $HTMLToReview + $HTMLToIgnore + $HTMLNonWindowsToReview + $HTMLNonWindowsComputersToIgnore + $HTMLWindowsComputersToMove + $HTMLNonWindowsComputersToMove + $HTMLWindowsComputersToDisable + $HTMLNonWindowsComputersToDisable + $HTMLWindowsComputersToDelete + $HTMLNonWindowsComputersToDelete
Write-Verbose -Message "Converting all HTML together and writing the output to $OutFilePath."
ConvertTo-html -Title "Inactive Computer Report" -Body $HTMLCode  -post $HTMLFooter -Head $HTMLhead | 
    Out-file $OutFilePath -Encoding ascii
#endregion Write HTML File

#region Compose E-Mail Message
Write-Verbose -Message "Option to send email is: $SendEmail"
if ($SendEmail)
{
	Write-Verbose -Message "Sending report through email to: "
    $EmailRecpients | ForEach-Object { Write-Verbose -Message $_}
    Write-Verbose -Message "Mail Message as follows."
    Write-Verbose -Message "EMAIL SERVER: $SMTPServer"
    Write-Verbose -Message "FROM: $EmailSender"
    Write-Verbose -Message "TO: $EmailRecpients"
	Write-Verbose -Message "SUBJECT: $SMTPServer"
	$parms = @{
		'BodyAsHtml' = $true;
		'Body' = ([string]$HTMLCode);
		'Subject' = $EmailSubject;
		'SmtpServer' = $SMTPServer;
		'To' = $EmailRecpients;
		'From' = $EmailSender
	}
	Send-MailMessage @parms
} # if $SendMail
#endregion Compose E-Mail Message

Write-Verbose -Message "Script complete."