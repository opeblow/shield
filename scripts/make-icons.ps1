Add-Type -AssemblyName System.Drawing
$dir = Join-Path $PSScriptRoot "..\extensions\browser"
foreach ($size in @(48, 128)) {
  $bmp = New-Object System.Drawing.Bitmap $size, $size
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $bg = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(13, 41, 37))
  $g.FillRectangle($bg, 0, 0, $size, $size)
  $fontSize = [math]::Round($size * 0.5)
  $font = New-Object System.Drawing.Font("Segoe UI", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
  $sf = New-Object System.Drawing.StringFormat
  $sf.Alignment = [System.Drawing.StringAlignment]::Center
  $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
  $brush = [System.Drawing.Brushes]::White
  $rect = New-Object System.Drawing.RectangleF(0, 0, $size, $size)
  $g.DrawString("S", $font, $brush, $rect, $sf)
  $g.Dispose()
  $bmp.Save((Join-Path $dir "icon-$size.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
}
Write-Output "wrote icons"