# PowerShell script to check AIT512 PA completion status

param(
    [string]$BasePath = "D:\First Week"
)

Write-Host "🔍 Checking AIT512 Programming Assignments in $BasePath" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Yellow
Write-Host ""

# Define PA folders (based on directory listing)
$paFolders = @(
    "A02-2",
    "A11-PA Fixed Capacity Bag",
    "A12-PA-Dynamic Capacity Bag",
    "A13 Linked-list Bags",
    "A21-PA1",
    "A21-PA2",
    "A22-PA1",
    "A22-PA2",
    "A31-PA",
    "A32-PA",
    "A33-PA Memory Analysis",
    "B11-PA",
    "B12-PA",
    "B13-PA",
    "B21-PA Top-Down",
    "B22-PA",
    "B23-PA Bottom-up Merge Sort"
)

# Initialize counters
$submitted = @()
$submittedNotGraded = @()
$readyToSubmit = @()
$incomplete = @()

function Check-PA-Completion {
    param([string]$FolderPath)

    $folderName = Split-Path $FolderPath -Leaf

    # Check if folder exists
    if (!(Test-Path $FolderPath)) {
        Write-Host "❌ Folder not found: $folderName" -ForegroundColor Red
        return "not_found"
    }

    Write-Host "📁 Checking: $folderName" -ForegroundColor Cyan

    # Get all files in the folder (recursive)
    $files = Get-ChildItem -Path $FolderPath -File -Recurse -ErrorAction SilentlyContinue

    # Check for completion indicators
    $hasJavaFiles = $files | Where-Object { $_.Extension -eq ".java" }
    $hasClassFiles = $files | Where-Object { $_.Extension -eq ".class" }
    $hasJarFiles = $files | Where-Object { $_.Extension -eq ".jar" }
    $hasAnswers = $files | Where-Object { $_.Name -like "*answer*" -or $_.Name -like "*Answers*" }
    $hasScreenshots = $files | Where-Object { $_.Name -like "*screenshot*" -or $_.Name -like "*screen*" -or $_.Extension -in @(".png", ".jpg", ".jpeg", ".gif") }
    $hasPDF = $files | Where-Object { $_.Extension -eq ".pdf" }
    $hasZip = $files | Where-Object { $_.Extension -eq ".zip" }

    # Determine completion status
    $hasCode = ($hasJavaFiles.Count -gt 0) -or ($hasClassFiles.Count -gt 0) -or ($hasJarFiles.Count -gt 0)
    $hasDocumentation = ($hasAnswers.Count -gt 0) -or ($hasPDF.Count -gt 0) -or ($hasScreenshots.Count -gt 0)

    Write-Host "   Code files: $($hasJavaFiles.Count) .java, $($hasClassFiles.Count) .class, $($hasJarFiles.Count) .jar" -ForegroundColor White
    Write-Host "   Documentation: $($hasAnswers.Count) answers, $($hasPDF.Count) PDFs, $($hasScreenshots.Count) screenshots" -ForegroundColor White
    Write-Host "   Archives: $($hasZip.Count) zip files" -ForegroundColor White

    # Logic for status determination
    if ($hasZip.Count -gt 0) {
        Write-Host "   ✅ Status: SUBMITTED (has zip file)" -ForegroundColor Green
        return "submitted"
    }
    elseif ($hasCode -and $hasDocumentation) {
        Write-Host "   🔄 Status: READY TO SUBMIT (has code + docs)" -ForegroundColor Yellow
        return "ready_to_submit"
    }
    elseif ($hasCode) {
        Write-Host "   ⚠️  Status: INCOMPLETE (has code but missing docs)" -ForegroundColor Red
        return "incomplete"
    }
    else {
        Write-Host "   ❓ Status: UNKNOWN (no clear indicators)" -ForegroundColor Gray
        return "unknown"
    }
}

# Check each PA folder
foreach ($pa in $paFolders) {
    $fullPath = Join-Path $BasePath $pa
    $status = Check-PA-Completion -FolderPath $fullPath

    switch ($status) {
        "submitted" { $submitted += $pa }
        "ready_to_submit" { $readyToSubmit += $pa }
        "incomplete" { $incomplete += $pa }
        default { $incomplete += $pa }
    }

    Write-Host ""
}

# Summary
Write-Host "📊 SUMMARY" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Yellow
Write-Host ""

Write-Host "✅ SUBMITTED ($($submitted.Count)):" -ForegroundColor Green
$submitted | ForEach-Object { Write-Host "   - $_" -ForegroundColor White }

Write-Host ""
Write-Host "🔄 READY TO SUBMIT ($($readyToSubmit.Count)):" -ForegroundColor Yellow
$readyToSubmit | ForEach-Object { Write-Host "   - $_" -ForegroundColor White }

Write-Host ""
Write-Host "⚠️  INCOMPLETE ($($incomplete.Count)):" -ForegroundColor Red
$incomplete | ForEach-Object { Write-Host "   - $_" -ForegroundColor White }

Write-Host ""
Write-Host "Total PA folders checked: $($paFolders.Count)" -ForegroundColor Cyan
Write-Host "Completion rate: $([math]::Round(($submitted.Count + $readyToSubmit.Count) / $paFolders.Count * 100, 1))%" -ForegroundColor Cyan

# Additional files found
Write-Host ""
Write-Host "📄 ADDITIONAL FILES FOUND:" -ForegroundColor Magenta
$additionalFiles = Get-ChildItem -Path $BasePath -File | Where-Object { $_.Name -like "*PA*" -or $_.Name -like "*answer*" }
$additionalFiles | ForEach-Object {
    Write-Host "   - $($_.Name)" -ForegroundColor Gray
}
}
