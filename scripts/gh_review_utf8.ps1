param(
    [Parameter(Mandatory = $true)]
    [string] $Repo,

    [Parameter(Mandatory = $true)]
    [int] $Pr,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $BodyFile,

    [ValidateSet("comment", "approve", "request-changes")]
    [string] $Mode = "comment"
)

$ErrorActionPreference = "Stop"

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$resolvedBodyFile = (Resolve-Path -LiteralPath $BodyFile).Path

switch ($Mode) {
    "comment" {
        gh pr comment $Pr --repo $Repo --body-file $resolvedBodyFile
        break
    }
    "approve" {
        gh pr review $Pr --repo $Repo --approve --body-file $resolvedBodyFile
        break
    }
    "request-changes" {
        gh pr review $Pr --repo $Repo --request-changes --body-file $resolvedBodyFile
        break
    }
}
