[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$assetDirectory = Join-Path $PSScriptRoot 'Assets'
$null = New-Item -ItemType Directory -Force -Path $assetDirectory
$source = [System.Drawing.Image]::FromFile((Join-Path $PSScriptRoot 'Artwork\locksmith.png'))
try {
    if ($source.Width -ne $source.Height) { throw 'Source icon must be square.' }
    foreach ($item in @(@('StoreLogo.png', 50), @('Square44x44Logo.png', 44), @('Square150x150Logo.png', 150), @('StoreIcon.png', 300))) {
        $size = [int]$item[1]
        $bitmap = [System.Drawing.Bitmap]::new($size, $size)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $graphics.DrawImage($source, 0, 0, $size, $size)
            $bitmap.Save((Join-Path $assetDirectory $item[0]), [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $graphics.Dispose()
            $bitmap.Dispose()
        }
    }
} finally {
    $source.Dispose()
}
