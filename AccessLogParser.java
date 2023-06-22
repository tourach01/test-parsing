import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AccessLogParser {
    private static final String LOG_REGEX = "\\[(.*?)\\] conn=(\\d+) op=(-?\\d+) msgId=(-?\\d+)";
    private static final Pattern LOG_PATTERN = Pattern.compile(LOG_REGEX);
    private static final String BIND_REGEX = "BIND dn=\"(.*?)\"";
    private static final String SOURCE_IP_REGEX = "connection.*?from (\\d+\\.\\d+\\.\\d+\\.\\d+)";
    private static final String LINE_SEPARATOR = System.lineSeparator();

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Veuillez fournir le nom du fichier access.log en tant que paramètre.");
            System.out.println("Utilisation : java AccessLogParser <chemin_vers_access.log>");
            System.exit(1);
        }

        String logFilePath = args[0];
        Path path = Paths.get(logFilePath);

        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            System.out.println("Le fichier " + logFilePath + " n'existe pas ou n'est pas un fichier régulier.");
            System.exit(1);
        }

        try (BufferedReader br = new BufferedReader(new FileReader(logFilePath), 8192)) {
            StringBuilder logEntryBuilder = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isEmpty()) {
                    processLogEntry(logEntryBuilder.toString());
                    logEntryBuilder.setLength(0); // Réinitialiser le contenu du StringBuilder
                } else {
                    logEntryBuilder.append(line).append(LINE_SEPARATOR);
                }
            }

            // Traiter la dernière entrée du journal si elle n'est pas vide
            if (logEntryBuilder.length() > 0) {
                processLogEntry(logEntryBuilder.toString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void processLogEntry(String logEntry) {
        Matcher matcher = LOG_PATTERN.matcher(logEntry);
        if (matcher.find()) {
            String timestamp = matcher.group(1);
            int connection = Integer.parseInt(matcher.group(2));
            int operation = Integer.parseInt(matcher.group(3));
            int messageId = Integer.parseInt(matcher.group(4));

            if (operation == 0) { // Vérifier si l'opération est un "BIND"
                String bindDn = extractBindDn(logEntry);
                String sourceIp = extractSourceIp(logEntry);
                System.out.println("Timestamp: " + timestamp + " | Connection: " + connection +
                        " | Operation: " + operation + " | Message ID: " + messageId +
                        " | BIND DN: " + bindDn + " | Source IP: " + sourceIp);
            }
        }
    }

    private static String extractBindDn(String logEntry) {
        Matcher matcher = Pattern.compile(BIND_REGEX).matcher(logEntry);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    private static String extractSourceIp(String logEntry) {
        Matcher matcher = Pattern.compile(SOURCE_IP_REGEX).matcher(logEntry);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }
}
