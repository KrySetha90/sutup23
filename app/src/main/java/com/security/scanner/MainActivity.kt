package com.security.scanner

import android.Manifest
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.OpenableColumns
import android.provider.Settings
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.*
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatusBadge: TextView
    private lateinit var tvCurrentTarget: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var tvScanResults: TextView
    private lateinit var scrollLog: ScrollView

    private var scanJob: Job? = null

    // Suspicious extensions and patterns
    private val highRiskExtensions = setOf("apk", "xapk", "exe", "bat", "sh", "elf", "so", "dex", "jar", "vbs", "ps1")
    private val suspiciousKeywords = listOf("payload", "inject", "rat_", "keylog", "trojan", "crack", "keygen", "hacktool", "exploit", "backdoor")
    private val dangerousPermissions = setOf(
        Manifest.permission.READ_SMS,
        Manifest.permission.RECEIVE_SMS,
        Manifest.permission.SEND_SMS,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.CAMERA,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.READ_CALL_LOG,
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
    )

    // File picker for "Upload Check"
    private val filePickerLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            runUploadFileCheck(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatusBadge = findViewById(R.id.tvStatusBadge)
        tvCurrentTarget = findViewById(R.id.tvCurrentTarget)
        progressBar = findViewById(R.id.progressBar)
        tvScanResults = findViewById(R.id.tvScanResults)
        scrollLog = findViewById(R.id.scrollLog)

        findViewById<MaterialButton>(R.id.btnQuickCheck).setOnClickListener {
            if (checkStoragePermission()) runQuickCheck()
        }

        findViewById<MaterialButton>(R.id.btnFullCheck).setOnClickListener {
            if (checkStoragePermission()) runFullFolderCheck()
        }

        findViewById<MaterialButton>(R.id.btnToolCheck).setOnClickListener {
            runToolAppCheck()
        }

        findViewById<MaterialButton>(R.id.btnUploadCheck).setOnClickListener {
            filePickerLauncher.launch(arrayOf("*/*"))
        }
    }

    private fun checkStoragePermission(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                appendLog("[!] Grant 'All Files Access' to scan storage folders.")
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
                return false
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), 101)
                return false
            }
        }
        return true
    }

    // 1. QUICK CHECK: Scans high-target directories (Download, Documents, Telegram/WhatsApp media)
    private fun runQuickCheck() {
        scanJob?.cancel()
        scanJob = CoroutineScope(Dispatchers.Main).launch {
            resetUI("⚡ QUICK SCAN RUNNING...")
            val root = Environment.getExternalStorageDirectory()
            val targetDirs = listOf(
                File(root, "Download"),
                File(root, "Documents"),
                File(root, "Bluetooth"),
                File(root, "Android/media")
            ).filter { it.exists() && it.isDirectory }

            var scanned = 0
            val threats = mutableListOf<String>()

            withContext(Dispatchers.IO) {
                val filesToScan = mutableListOf<File>()
                targetDirs.forEach { dir ->
                    dir.walkTopDown().maxDepth(3).filter { it.isFile }.forEach { filesToScan.add(it) }
                }
                val total = filesToScan.size.coerceAtLeast(1)

                for (file in filesToScan) {
                    scanned++
                    val risk = evaluateFileRisk(file)
                    if (risk != null) threats.add(risk)

                    if (scanned % 15 == 0 || scanned == total) {
                        withContext(Dispatchers.Main) {
                            progressBar.progress = (scanned * 100) / total
                            tvCurrentTarget.text = "Checking: ${file.name}"
                        }
                    }
                }
            }

            finishScan("Quick Check", scanned, threats)
        }
    }

    // 2. LATE / FULL CHECK: Deep recursive scan of ALL folders on internal storage
    private fun runFullFolderCheck() {
        scanJob?.cancel()
        scanJob = CoroutineScope(Dispatchers.Main).launch {
            resetUI("🔍 FULL STORAGE SCAN RUNNING...")
            val root = Environment.getExternalStorageDirectory()
            var scanned = 0
            val threats = mutableListOf<String>()

            withContext(Dispatchers.IO) {
                val allFiles = root.walkTopDown()
                    .onEnter { dir -> !dir.name.startsWith(".thumbnails") }
                    .filter { it.isFile }
                    .toList()
                val total = allFiles.size.coerceAtLeast(1)

                for (file in allFiles) {
                    scanned++
                    val risk = evaluateFileRisk(file)
                    if (risk != null) threats.add(risk)

                    if (scanned % 30 == 0 || scanned == total) {
                        withContext(Dispatchers.Main) {
                            progressBar.progress = (scanned * 100) / total
                            tvCurrentTarget.text = "Folder: ${file.parentFile?.name}/${file.name}"
                        }
                    }
                }
            }

            finishScan("Full Folder Check", scanned, threats)
        }
    }

    // 3. TOOL CHECK: Audits installed apps, sideloaded APKs, and dangerous permission combos
    private fun runToolAppCheck() {
        scanJob?.cancel()
        scanJob = CoroutineScope(Dispatchers.Main).launch {
            resetUI("🛠️ AUDITING INSTALLED APPS & TOOLS...")
            val pm = packageManager
            val flaggedApps = mutableListOf<String>()
            var totalApps = 0

            withContext(Dispatchers.IO) {
                val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                val userApps = packages.filter { (it.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
                totalApps = userApps.size

                userApps.forEachIndexed { idx, pkgInfo ->
                    val appName = pkgInfo.applicationInfo.loadLabel(pm).toString()
                    val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        pm.getInstallSourceInfo(pkgInfo.packageName).installingPackageName
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getInstallerPackageName(pkgInfo.packageName)
                    }

                    val requestedPerms = pkgInfo.requestedPermissions?.toList() ?: emptyList()
                    val riskyPerms = requestedPerms.filter { it in dangerousPermissions }
                    val isSideloaded = installer == null || installer != "com.android.vending"

                    if (riskyPerms.size >= 3 || (isSideloaded && riskyPerms.isNotEmpty())) {
                        val sourceTag = if (isSideloaded) "Sideloaded (${installer ?: "Unknown"})" else "Play Store"
                        flaggedApps.add(
                            "• $appName (${pkgInfo.packageName})
  Source: $sourceTag | High-Risk Perms: ${riskyPerms.size}"
                        )
                    }

                    withContext(Dispatchers.Main) {
                        progressBar.progress = ((idx + 1) * 100) / totalApps.coerceAtLeast(1)
                        tvCurrentTarget.text = "Auditing: $appName"
                    }
                }
            }

            finishScan("Tool & App Audit", totalApps, flaggedApps)
        }
    }

    // 4. UPLOAD CHECK: Inspects any user-selected file (SHA-256 hash, header magic bytes, extension mismatch)
    private fun runUploadFileCheck(uri: Uri) {
        scanJob?.cancel()
        scanJob = CoroutineScope(Dispatchers.Main).launch {
            resetUI("📤 INSPECTING UPLOADED FILE...")
            progressBar.progress = 35

            val report = withContext(Dispatchers.IO) {
                var fileName = "unknown_file"
                var fileSize = 0L
                contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (cursor.moveToFirst()) {
                        if (nameIdx >= 0) fileName = cursor.getString(nameIdx)
                        if (sizeIdx >= 0) fileSize = cursor.getLong(sizeIdx)
                    }
                }

                val sha256 = computeSha256(uri)
                val magicHeader = readMagicBytes(uri)
                val ext = fileName.substringAfterLast('.', "").lowercase()

                val findings = mutableListOf<String>()
                if (ext in highRiskExtensions) {
                    findings.add("⚠️ Executable/Installer extension (.$ext)")
                }
                if (magicHeader.startsWith("504B0304") && ext !in setOf("zip", "apk", "xapk", "jar", "docx", "xlsx")) {
                    findings.add("🚨 Hidden ZIP/APK archive disguised as .$ext!")
                }
                if (magicHeader.startsWith("7F454C46") || magicHeader.startsWith("4D5A")) {
                    findings.add("🚨 Native Binary Executable (ELF/MZ) detected!")
                }
                if (suspiciousKeywords.any { fileName.lowercase().contains(it) }) {
                    findings.add("⚠️ Filename contains threat keyword")
                }

                buildString {
                    appendLine("=== UPLOAD FILE ANALYSIS ===")
                    appendLine("File Name : $fileName")
                    appendLine("File Size : ${fileSize / 1024} KB ($fileSize bytes)")
                    appendLine("Magic Hex : $magicHeader")
                    appendLine("SHA-256   : $sha256")
                    appendLine("----------------------------")
                    if (findings.isEmpty()) {
                        appendLine("✅ VERDICT: CLEAN (No malicious signature or spoofing detected)")
                    } else {
                        appendLine("🚨 VERDICT: SUSPICIOUS")
                        findings.forEach { appendLine(it) }
                    }
                }
            }

            progressBar.progress = 100
            tvCurrentTarget.text = "File analysis complete"
            val isSuspicious = report.contains("SUSPICIOUS")
            tvStatusBadge.text = if (isSuspicious) "⚠️ THREAT DETECTED IN FILE" else "✅ FILE SAFE"
            tvStatusBadge.setTextColor(
                ContextCompat.getColor(this@MainActivity, if (isSuspicious) R.color.status_danger else R.color.status_safe)
            )
            tvScanResults.text = report
        }
    }

    private fun evaluateFileRisk(file: File): String? {
        val nameLower = file.name.lowercase()
        val ext = file.extension.lowercase()

        // Check hidden executable or double extensions (e.g., photo.jpg.apk)
        if (nameLower.matches(Regex(".*\.(jpg|png|pdf|mp4|txt|doc)\.(apk|exe|sh|bat)$"))) {
            return "🚨 Double-Extension Spoof: ${file.absolutePath}"
        }
        if (ext in highRiskExtensions) {
            return "⚠️ Installer/Binary (.$ext): ${file.name} (${file.parentFile?.name})"
        }
        if (suspiciousKeywords.any { nameLower.contains(it) }) {
            return "🚨 Suspicious Name Match: ${file.absolutePath}"
        }
        return null
    }

    private fun computeSha256(uri: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256")
        contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun readMagicBytes(uri: Uri): String {
        contentResolver.openInputStream(uri)?.use { input: InputStream ->
            val header = ByteArray(8)
            val count = input.read(header)
            if (count > 0) {
                return header.take(count).joinToString("") { "%02X".format(it) }
            }
        }
        return "UNKNOWN"
    }

    private fun resetUI(statusText: String) {
        tvStatusBadge.text = statusText
        tvStatusBadge.setTextColor(ContextCompat.getColor(this, R.color.accent_blue))
        progressBar.progress = 0
        tvScanResults.text = "Initializing scan engine...
"
    }

    private fun finishScan(scanType: String, totalItems: Int, findings: List<String>) {
        progressBar.progress = 100
        tvCurrentTarget.text = "$scanType completed ($totalItems items checked)"

        if (findings.isEmpty()) {
            tvStatusBadge.text = "✅ NO THREATS FOUND"
            tvStatusBadge.setTextColor(ContextCompat.getColor(this, R.color.status_safe))
            tvScanResults.text = "=== $scanType REPORT ===
Items Scanned: $totalItems
Threats Found: 0

Your device and scanned directories look clean."
        } else {
            tvStatusBadge.text = "⚠️ ${findings.size} ITEMS FLAGGED"
            tvStatusBadge.setTextColor(ContextCompat.getColor(this, R.color.status_warn))
            val sb = StringBuilder()
            sb.appendLine("=== $scanType REPORT ===")
            sb.appendLine("Items Scanned: $totalItems | Flagged: ${findings.size}
")
            findings.take(150).forEach { sb.appendLine(it) }
            if (findings.size > 150) sb.appendLine("
...and ${findings.size - 150} more items.")
            tvScanResults.text = sb.toString()
        }
    }

    private fun appendLog(msg: String) {
        tvScanResults.append("
$msg")
        scrollLog.post { scrollLog.fullScroll(ScrollView.FOCUS_DOWN) }
    }
}
