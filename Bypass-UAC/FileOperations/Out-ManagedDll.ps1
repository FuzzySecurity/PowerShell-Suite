function Out-ManagedDll
{
    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [String]
        $FilePath
    )

    $Path = Resolve-Path $FilePath

    if (! [IO.File]::Exists($Path))
    {
        Throw "$Path does not exist."
    }

    $FileBytes = [System.IO.File]::ReadAllBytes($Path)

    if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')
    {
        Throw "$Path is not a valid executable."
    }

    $Length = $FileBytes.Length
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($FileBytes, 0, $FileBytes.Length)
    $DeflateStream.Dispose()
    $CompressedFileBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedFile = [Convert]::ToBase64String($CompressedFileBytes)

    Write-Verbose "Compression ratio: $(($EncodedCompressedFile.Length/$FileBytes.Length).ToString('#%'))"

    $Output = @"
`$EncodedCompressedFile = @'
$EncodedCompressedFile
'@
`$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`$EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
`$UncompressedFileBytes = New-Object Byte[]($Length)
`$DeflatedStream.Read(`$UncompressedFileBytes, 0, $Length) | Out-Null
[Reflection.Assembly]::Load(`$UncompressedFileBytes)
"@

    Write-Output $Output
}