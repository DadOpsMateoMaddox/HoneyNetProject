# PowerShell script to find  Class folder with Java assignments

param(
    [string]$SearchPath = "C:\",
    [string]$ClassName = ""
)

Write-Host "Searching for $ClassName folder with Java assignments..." -ForegroundColor Green
Write-Host "Search path: $SearchPath" -ForegroundColor Yellow
Write-Host ""

# Function to search for directories containing the class name
function Find-ClassFolders {
    param([string]$Path, [string]$Class)

    try {
        $folders = Get-ChildItem -Path $Path -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$Class*" -or $_.FullName -like "*$Class*" }

        return $folders
    }
    catch {
        Write-Host "Error accessing path: $Path" -ForegroundColor Red
        return $null
    }
}

# Function to check for Java files in a directory
function Check-JavaFiles {
    param([string]$Path)

    try {
        $javaFiles = Get-ChildItem -Path $Path -File -Recurse -Include "*.java" -ErrorAction SilentlyContinue
        $classFiles = Get-ChildItem -Path $Path -File -Recurse -Include "*.class" -ErrorAction SilentlyContinue
        $jarFiles = Get-ChildItem -Path $Path -File -Recurse -Include "*.jar" -ErrorAction SilentlyContinue

        $totalFiles = ($javaFiles | Measure-Object).Count + ($classFiles | Measure-Object).Count + ($jarFiles | Measure-Object).Count

        return @{
            JavaFiles = $javaFiles
            ClassFiles = $classFiles
            JarFiles = $jarFiles
            TotalCount = $totalFiles
        }
    }
    catch {
        return @{
            JavaFiles = @()
            ClassFiles = @()
            JarFiles = @()
            TotalCount = 0
        }
    }
}

# Main search logic
$foundFolders = Find-ClassFolders -Path $SearchPath -Class $ClassName

if ($foundFolders -and $foundFolders.Count -gt 0) {
    Write-Host "Found $($foundFolders.Count) potential $ClassName folders:" -ForegroundColor Green
    Write-Host ""

    foreach ($folder in $foundFolders) {
        Write-Host "📁 Folder: $($folder.FullName)" -ForegroundColor Cyan

        $javaInfo = Check-JavaFiles -Path $folder.FullName

        if ($javaInfo.TotalCount -gt 0) {
            Write-Host "   ✅ Contains Java files: $($javaInfo.TotalCount) total" -ForegroundColor Green
            Write-Host "      - .java files: $($javaInfo.JavaFiles.Count)" -ForegroundColor White
            Write-Host "      - .class files: $($javaInfo.ClassFiles.Count)" -ForegroundColor White
            Write-Host "      - .jar files: $($javaInfo.JarFiles.Count)" -ForegroundColor White

            # List some Java files
            if ($javaInfo.JavaFiles.Count -gt 0) {
                Write-Host "      📄 Java files found:" -ForegroundColor Yellow
                $javaInfo.JavaFiles | Select-Object -First 5 | ForEach-Object {
                    Write-Host "         - $($_.Name)" -ForegroundColor Gray
                }
                if ($javaInfo.JavaFiles.Count -gt 5) {
                    Write-Host "         ... and $($javaInfo.JavaFiles.Count - 5) more" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "   ❌ No Java files found in this folder" -ForegroundColor Red
        }

        Write-Host ""
    }
} else {
    Write-Host "❌ No folders containing '$ClassName' found in $SearchPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Suggestions:" -ForegroundColor Yellow
    Write-Host "1. Try a different search path (e.g., D:\ or your user folder)" -ForegroundColor White
    Write-Host "2. Check if the folder name contains variations like 'AIT-512' or '512'" -ForegroundColor White
    Write-Host "3. Search for common Java assignment folder names" -ForegroundColor White
}

Write-Host ""
Write-Host "Search completed." -ForegroundColor Green
