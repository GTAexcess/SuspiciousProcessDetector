import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.regex.Pattern;

/**
 * SuspiciousProcessDetector
 * Author: Mohammad Ali
 * Description: Scans running processes and flags suspicious or uncommon processes.
 */
public class SuspiciousProcessDetector {

    // Known suspicious patterns (can be extended)
    private static final String[] SUSPICIOUS_KEYWORDS = {
        "mimikatz", "powershell", "nc.exe", "cmd.exe /c", "cscript", "wscript", "mshta", "rundll32", "remote.exe", "taskkill"
    };

    public static void main(String[] args) {
        System.out.println("🔍 Suspicious Process Detector - Advanced Mode");
        System.out.println("---------------------------------------------");

        try {
            List<String> processList = getRunningProcesses();
            List<String> flagged = new ArrayList<>();

            for (String proc : processList) {
                for (String keyword : SUSPICIOUS_KEYWORDS) {
                    if (Pattern.compile(Pattern.quote(keyword), Pattern.CASE_INSENSITIVE).matcher(proc).find()) {
                        flagged.add(proc);
                        break;
                    }
                }
            }

            if (flagged.isEmpty()) {
                System.out.println("✅ No suspicious processes found.");
            } else {
                System.out.println("🚨 Suspicious processes detected:");
                for (String s : flagged) {
                    System.out.println("[ALERT] " + s);
                }
            }

        } catch (Exception e) {
            System.err.println("[ERROR] Failed to scan processes: " + e.getMessage());
        }
    }

    private static List<String> getRunningProcesses() throws Exception {
        List<String> processes = new ArrayList<>();
        Process process;

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            process = Runtime.getRuntime().exec("tasklist");
        } else {
            process = Runtime.getRuntime().exec("ps -eo comm,args");
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            processes.add(line.trim());
        }

        return processes;
    }
}
