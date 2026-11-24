using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace DefenderGuard
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            Loaded += async (_, _) => await RefreshDefenderStatusAsync();
        }

        private void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogConsole.AppendText($"\n[{DateTime.Now:HH:mm:ss}] {message}");
                LogConsole.ScrollToEnd();
            });
        }

        private async Task<(int ExitCode, string Output, string Error)> RunPowerShellAsync(string command)
        {
            return await Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi)!;
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                return (proc.ExitCode, output.Trim(), error.Trim());
            });
        }

        private static bool GetSafeBool(JsonElement root, string name)
        {
            if (root.TryGetProperty(name, out var prop) && (prop.ValueKind == JsonValueKind.True || prop.ValueKind == JsonValueKind.False))
                return prop.GetBoolean();
            return false;
        }

        private static long GetSafeLong(JsonElement root, string name, long fallback = -1)
        {
            if (root.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.Number && prop.TryGetInt64(out long val))
                return val;
            return fallback;
        }

        private static string GetSafeString(JsonElement root, string name, string fallback = "Unknown")
        {
            if (root.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
                return prop.GetString() ?? fallback;
            return fallback;
        }

        private void SetBannerState(bool isProtected, string title, string subtitle)
        {
            if (isProtected)
            {
                StatusBanner.Background = new SolidColorBrush(Color.FromRgb(236, 253, 245));
                StatusBanner.BorderBrush = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                StatusBadge.Background = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                StatusIcon.Text = "✓";
                StatusTitle.Foreground = new SolidColorBrush(Color.FromRgb(6, 95, 70));
                StatusSubtitle.Foreground = new SolidColorBrush(Color.FromRgb(4, 120, 87));
            }
            else
            {
                StatusBanner.Background = new SolidColorBrush(Color.FromRgb(254, 242, 242));
                StatusBanner.BorderBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                StatusBadge.Background = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                StatusIcon.Text = "!";
                StatusTitle.Foreground = new SolidColorBrush(Color.FromRgb(153, 27, 27));
                StatusSubtitle.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
            }
            StatusTitle.Text = title;
            StatusSubtitle.Text = subtitle;
        }

        private async Task RefreshDefenderStatusAsync()
        {
            Log("Refreshing Microsoft Defender status...");
            var svcCheck = await RunPowerShellAsync("(Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status");
            string svcStatus = svcCheck.Output;

            var result = await RunPowerShellAsync("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,AntivirusSignatureVersion,AntivirusSignatureAge,QuickScanAge,FullScanAge,AMEngineVersion,AMRunningMode | ConvertTo-Json");

            if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Output))
            {
                Log($"Failed to read status (WinDefend: {svcStatus}): {result.Error}");
                SetBannerState(false, "Defender Service Stopped / Unavailable",
                    "Microsoft Defender (WinDefend) is stopped or another antivirus is managing this PC.");
                SidebarEngineText.Text = $"Service: {(string.IsNullOrWhiteSpace(svcStatus) ? "Stopped" : svcStatus)}";
                return;
            }

            try
            {
                using var doc = JsonDocument.Parse(result.Output);
                var root = doc.RootElement;

                bool avEnabled = GetSafeBool(root, "AntivirusEnabled");
                bool rtEnabled = GetSafeBool(root, "RealTimeProtectionEnabled");
                bool bmEnabled = GetSafeBool(root, "BehaviorMonitorEnabled");
                bool tamper = GetSafeBool(root, "IsTamperProtected");
                string sigVer = GetSafeString(root, "AntivirusSignatureVersion");
                long sigAge = GetSafeLong(root, "AntivirusSignatureAge");
                string engineVer = GetSafeString(root, "AMEngineVersion");
                long quickAge = GetSafeLong(root, "QuickScanAge");
                string runningMode = GetSafeString(root, "AMRunningMode", "Normal");

                SidebarEngineText.Text = $"Engine: {engineVer}";
                SidebarSignatureText.Text = $"Defs: {sigVer}";

                CardRealtimeValue.Text = rtEnabled ? "Active (ON)" : "Disabled (OFF)";
                CardRealtimeValue.Foreground = new SolidColorBrush(rtEnabled ? Color.FromRgb(5, 150, 105) : Color.FromRgb(220, 38, 38));

                CardBehaviorValue.Text = bmEnabled ? "Active (ON)" : "Disabled (OFF)";
                CardTamperValue.Text = tamper ? "Protected (ON)" : "Unlocked (OFF)";

                CardSignatureDetails.Text = sigAge >= 0 && sigAge < 9999
                    ? $"Version: {sigVer}\nUpdated: {sigAge} day(s) ago"
                    : $"Version: {sigVer}\nMode: {runningMode}";

                CardScanDetails.Text = quickAge >= 0 && quickAge < 9999
                    ? $"Last Quick Scan: {quickAge} day(s) ago"
                    : "Last Quick Scan: No recent scan recorded";

                if (avEnabled && rtEnabled)
                {
                    SetBannerState(true, "You're Protected",
                        $"Microsoft Defender Real-Time Protection is active (Mode: {runningMode}).");
                }
                else if (svcStatus != "Running")
                {
                    SetBannerState(false, "Defender Service Not Running",
                        $"WinDefend status: {svcStatus}. Another antivirus may be active, or Defender is disabled.");
                }
                else
                {
                    SetBannerState(false, "Action Needed: Protection Paused",
                        $"Real-Time Protection is off (Mode: {runningMode}).");
                }

                Log("Status refreshed successfully.");
            }
            catch (Exception ex)
            {
                Log($"Parse error: {ex.Message}");
            }
        }

        private void SwitchView(UIElement activeView)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewScan.Visibility = Visibility.Collapsed;
            ViewProtection.Visibility = Visibility.Collapsed;
            ViewThreats.Visibility = Visibility.Collapsed;
            ViewUpdates.Visibility = Visibility.Collapsed;
            activeView.Visibility = Visibility.Visible;
        }

        private void NavDashboard_Click(object sender, RoutedEventArgs e) => SwitchView(ViewDashboard);
        private void NavScan_Click(object sender, RoutedEventArgs e) => SwitchView(ViewScan);
        private void NavProtection_Click(object sender, RoutedEventArgs e) => SwitchView(ViewProtection);
        private void NavThreats_Click(object sender, RoutedEventArgs e) => SwitchView(ViewThreats);
        private void NavUpdates_Click(object sender, RoutedEventArgs e) => SwitchView(ViewUpdates);

        private async void RefreshStatus_Click(object sender, RoutedEventArgs e) => await RefreshDefenderStatusAsync();

        private async void QuickScan_Click(object sender, RoutedEventArgs e)
        {
            Log("Starting Quick Scan...");
            var res = await RunPowerShellAsync("Start-MpScan -ScanType QuickScan");
            if (res.ExitCode == 0)
            {
                Log("Quick Scan completed.");
            }
            else if (res.Error.Contains("0x800106ba", StringComparison.OrdinalIgnoreCase))
            {
                Log("Scan failed (0x800106ba): Windows Defender service (WinDefend) is stopped or another antivirus is active.");
            }
            else
            {
                Log($"Quick Scan error: {res.Error}");
            }
            await RefreshDefenderStatusAsync();
        }

        private async void FullScan_Click(object sender, RoutedEventArgs e)
        {
            Log("Starting Full Scan (this may take a while)...");
            var res = await RunPowerShellAsync("Start-MpScan -ScanType FullScan");
            Log(res.ExitCode == 0 ? "Full Scan completed." : $"Full Scan error: {res.Error}");
            await RefreshDefenderStatusAsync();
        }

        private async void CustomScan_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog { Title = "Select Folder to Scan" };
            if (dlg.ShowDialog() == true)
            {
                string path = dlg.FolderName;
                Log($"Starting Custom Scan on: {path}");
                var res = await RunPowerShellAsync($"Start-MpScan -ScanType CustomScan -ScanPath '{path.Replace("'", "''")}'");
                Log(res.ExitCode == 0 ? $"Custom Scan finished for {path}." : $"Custom Scan error: {res.Error}");
            }
        }

        private async void UpdateSignatures_Click(object sender, RoutedEventArgs e)
        {
            Log("Updating virus & spyware definitions...");
            var res = await RunPowerShellAsync("Update-MpSignature");
            Log(res.ExitCode == 0 ? "Virus definitions updated." : $"Update error: {res.Error}");
            await RefreshDefenderStatusAsync();
        }

        private async void EnableRealtime_Click(object sender, RoutedEventArgs e)
        {
            Log("Enabling Real-Time Protection...");
            var res = await RunPowerShellAsync("Set-MpPreference -DisableRealtimeMonitoring $false");
            Log(res.ExitCode == 0 ? "Real-Time Protection enabled." : $"Failed (Tamper Protection may block this): {res.Error}");
            await RefreshDefenderStatusAsync();
        }

        private async void DisableRealtime_Click(object sender, RoutedEventArgs e)
        {
            Log("Attempting to disable Real-Time Protection...");
            var res = await RunPowerShellAsync("Set-MpPreference -DisableRealtimeMonitoring $true");
            Log(res.ExitCode == 0 ? "Real-Time Protection disabled." : $"Blocked (likely by Tamper Protection): {res.Error}");
            await RefreshDefenderStatusAsync();
        }

        private async void EnableCloud_Click(object sender, RoutedEventArgs e)
        {
            Log("Setting Cloud-Delivered Protection to Advanced...");
            var res = await RunPowerShellAsync("Set-MpPreference -MAPSReporting Advanced");
            Log(res.ExitCode == 0 ? "Cloud protection set to Advanced." : $"Error: {res.Error}");
        }

        private async void EnablePua_Click(object sender, RoutedEventArgs e)
        {
            Log("Enabling PUA Protection...");
            var res = await RunPowerShellAsync("Set-MpPreference -PUAProtection Enabled");
            Log(res.ExitCode == 0 ? "PUA Protection enabled." : $"Error: {res.Error}");
        }

        private async void LoadThreats_Click(object sender, RoutedEventArgs e)
        {
            Log("Querying threat detection history...");
            var res = await RunPowerShellAsync("Get-MpThreatDetection | Select-Object -First 20 ThreatID,InitialDetectionTime,ActionSuccess,Resources | Format-List | Out-String");
            ThreatsTextBox.Text = string.IsNullOrWhiteSpace(res.Output)
                ? "No recent threats detected on this PC."
                : res.Output;
            Log("Threat history loaded.");
        }

        private async void CheckFirewall_Click(object sender, RoutedEventArgs e)
        {
            Log("Checking Windows Firewall profiles...");
            var res = await RunPowerShellAsync("Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table -AutoSize | Out-String");
            FirewallStatusText.Text = string.IsNullOrWhiteSpace(res.Output)
                ? $"Unable to read firewall profiles: {res.Error}"
                : res.Output;
            Log("Firewall check complete.");
        }

        private void OpenNativeSecurity_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(new ProcessStartInfo("windowsdefender:") { UseShellExecute = true });
        }
    }
}
