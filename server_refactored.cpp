#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctime>
#include <random>
#include <chrono>
#include <algorithm>
#include <cctype>

using namespace std;

// --- Simple in-memory data ---
unordered_map<string, string> users = {
    {"student1", "pass1"},
    {"student2", "pass2"},
    {"student3", "pass3"}
};

unordered_map<string, vector<bool>> user_progress = {
    {"student1", {false, false, false}},
    {"student2", {false, false, false}},
    {"student3", {false, false, false}}
};

// session_id -> username
unordered_map<string, string> sessions;

// Read a file from www/ and return its contents
string readFileContent(const string &path) {
    ifstream file("www/" + path);
    if (!file.is_open()) return "";
    stringstream ss; ss << file.rdbuf();
    return ss.str();
}

// Very small HTML escape (protect against simple XSS from username insertion)
string html_escape(const string &s) {
    string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c; break;
        }
    }
    return out;
}

// URL decode helper
string url_decode(const string &str) {
    string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int val = 0;
            if (sscanf(str.substr(i + 1, 2).c_str(), "%x", &val) == 1) {
                result += static_cast<char>(val);
                i += 2;
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

// Parse a urlencoded body and get the value for key
string get_form_value(const string &body, const string &key) {
    string needle = key + "=";
    size_t pos = body.find(needle);
    if (pos == string::npos) return "";
    size_t start = pos + needle.length();
    size_t end = body.find('&', start);
    string val = body.substr(start, (end == string::npos) ? string::npos : end - start);
    return val;
}

// Generate a session id using random_device + timestamp
string generate_session() {
    static random_device rd;
    static mt19937_64 gen(rd());
    uint64_t r = gen();
    auto now = chrono::high_resolution_clock::now().time_since_epoch().count();
    stringstream ss;
    ss << hex << r << ":" << now;
    return ss.str();
}

// Parse request headers into a map
map<string, string> parse_headers(const string &header_block) {
    map<string, string> headers;
    stringstream ss(header_block);
    string line;
    // first line is request line (handled elsewhere)
    getline(ss, line);
    while (getline(ss, line)) {
        if (line.empty() || line == "\r") break;
        size_t colon = line.find(':');
        if (colon != string::npos) {
            string name = line.substr(0, colon);
            string value = line.substr(colon + 1);
            // trim
            while (!value.empty() && isspace((unsigned char)value.front())) value.erase(value.begin());
            while (!value.empty() && (value.back()=='\r' || isspace((unsigned char)value.back()))) value.pop_back();
            // canonicalize header name to lowercase
            transform(name.begin(), name.end(), name.begin(), ::tolower);
            headers[name] = value;
        }
    }
    return headers;
}

// Extract cookie named 'session' from Cookie header
string get_session_user_from_headers(const map<string,string> &headers) {
    auto it = headers.find("cookie");
    if (it == headers.end()) return "";
    string cookies = it->second; // e.g. "session=abc; other=..."
    size_t pos = cookies.find("session=");
    if (pos == string::npos) return "";
    size_t start = pos + 8;
    size_t end = cookies.find(';', start);
    string session_id = cookies.substr(start, (end==string::npos) ? string::npos : end - start);
    if (sessions.count(session_id)) return sessions.at(session_id);
    return "";
}

// Serve a file with proper headers
string serveFile(const string &path) {
    string content = readFileContent(path);
    if (content.empty()) return "HTTP/1.1 404 Not Found\r\n\r\nPage Not Found";
    string content_type = "text/html";
    if (path.find(".css") != string::npos) content_type = "text/css";
    if (path.find(".js") != string::npos) content_type = "application/javascript";
    string header = "HTTP/1.1 200 OK\r\nContent-Type: " + content_type + "\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n";
    return header + content;
}

// Robust read: read until headers found and then read body if Content-Length present
bool read_full_request(int sock, string &out) {
    out.clear();
    const size_t BUF = 4096;
    char buf[BUF];
    ssize_t n;
    // read until we have headers
    while (true) {
        n = read(sock, buf, BUF);
        if (n <= 0) break;
        out.append(buf, n);
        if (out.find("\r\n\r\n") != string::npos) break;
        // if the request is huge, avoid infinite loop
        if (out.size() > 64 * 1024) break;
    }
    if (out.empty()) return false;
    size_t hdr_end = out.find("\r\n\r\n");
    if (hdr_end == string::npos) return true; // only headers so far
    string header_block = out.substr(0, hdr_end + 4);
    auto headers = parse_headers(header_block);
    auto it = headers.find("content-length");
    if (it != headers.end()) {
        size_t content_length = stoi(it->second);
        size_t have = out.size() - (hdr_end + 4);
        while (have < content_length) {
            n = read(sock, buf, BUF);
            if (n <= 0) break;
            out.append(buf, n);
            have = out.size() - (hdr_end + 4);
            if (out.size() > 1024 * 1024) break; // limit
        }
    }
    return true;
}

int main() {
    cerr << "Starting refactored server..." << endl;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 10) < 0) { perror("listen"); return 1; }

    cout << "[*] CTF Server running on http://localhost:8080 ..." << endl;

    while (true) {
        int new_socket = accept(server_fd, NULL, NULL);
        if (new_socket < 0) continue;

        string request;
        if (!read_full_request(new_socket, request)) {
            close(new_socket);
            continue;
        }

        size_t hdr_end = request.find("\r\n\r\n");
        string header_block = (hdr_end == string::npos) ? request : request.substr(0, hdr_end + 4);
        string body = (hdr_end == string::npos) ? string() : request.substr(hdr_end + 4);
        auto headers = parse_headers(header_block);

        string method, path;
        {
            stringstream ss(header_block);
            ss >> method >> path;
        }

        string response;

        if (method == "POST" && path == "/login") {
            string user = url_decode(get_form_value(body, "user"));
            string pass = url_decode(get_form_value(body, "pass"));
            if (users.count(user) && users[user] == pass) {
                string session_id = generate_session();
                sessions[session_id] = user;
                response = string("HTTP/1.1 302 Found\r\nSet-Cookie: session=") + session_id + "; Path=/; Max-Age=3600\r\nLocation: /dashboard\r\nContent-Length: 0\r\n\r\n";
            } else {
                string content = "INVALID_CREDENTIALS";
                response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
            }

        } else if ((method == "GET" || method == "POST") && path == "/dashboard") {
            string user = get_session_user_from_headers(headers);
            if (user.empty()) {
                response = "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n";
            } else {
                string content = readFileContent("dashboard.html");
                if (!content.empty()) {
                    size_t pos;
                    pos = content.find("data-username=\"\"");
                    if (pos != string::npos) content.replace(pos, 16, string("data-username=\"") + html_escape(user) + "\"");
                    pos = content.find("data-flag1=\"false\"");
                    if (pos != string::npos) content.replace(pos, 18, string("data-flag1=\"") + (user_progress[user][0] ? "true" : "false") + "\"");
                    pos = content.find("data-flag2=\"false\"");
                    if (pos != string::npos) content.replace(pos, 18, string("data-flag2=\"") + (user_progress[user][1] ? "true" : "false") + "\"");
                    pos = content.find("data-flag3=\"false\"");
                    if (pos != string::npos) content.replace(pos, 18, string("data-flag3=\"") + (user_progress[user][2] ? "true" : "false") + "\"");
                }
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
            }

        } else if (method == "GET" && path == "/get-progress") {
            string user = get_session_user_from_headers(headers);
            if (user.empty()) {
                response = "HTTP/1.1 401 Unauthorized\r\n\r\n{}";
            } else {
                string json = "{";
                json += "\"flag1\":" + string(user_progress[user][0] ? "true" : "false") + ",";
                json += "\"flag2\":" + string(user_progress[user][1] ? "true" : "false") + ",";
                json += "\"flag3\":" + string(user_progress[user][2] ? "true" : "false");
                json += "}";
                response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + to_string(json.size()) + "\r\n\r\n" + json;
            }

        } else if (method == "POST" && path == "/submit-flag") {
            string user = get_session_user_from_headers(headers);
            if (user.empty()) {
                response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
            } else {
                string flag_val = url_decode(get_form_value(body, "flag_val"));
                bool is_correct = false;
                int flag_index = -1;
                if (flag_val == "{SOURCE_CODE_MASTER_2025}") { user_progress[user][0] = true; is_correct = true; flag_index = 0; }
                else if (flag_val == "{DIR_ENUM_PRO_99}") { user_progress[user][1] = true; is_correct = true; flag_index = 1; }
                else if (flag_val == "{BRUTE_FORCE_SUCCESS_882}") { user_progress[user][2] = true; is_correct = true; flag_index = 2; }

                if (is_correct) {
                    string content = string("[+] Flag ") + to_string(flag_index + 1) + " Correct!";
                    response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
                } else {
                    string content = "[-] Wrong flag. Try again!";
                    response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
                }
            }

        } else if (method == "GET" && path == "/admin") {
            response = serveFile("admin.html");

        } else if (method == "POST" && path == "/admin-login") {
            string admin_user = get_form_value(body, "user");
            string admin_pass = get_form_value(body, "pass");
            if (admin_user == "admin" && admin_pass == "admin123") {
                string content = "<html><body style='font-family: monospace; text-align: center; padding: 50px; background: #0a0a0a; color: #00ff00;'><h1>[+] ACCESS GRANTED</h1><hr><h2 style='color: #fbbf24; margin-top: 30px;'>FLAG 3: {BRUTE_FORCE_SUCCESS_882}</h2><p style='margin-top: 20px;'>Copy this flag and submit it in the dashboard!</p></body></html>";
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
            } else {
                string content = "<html><body style='font-family: monospace; text-align: center; padding: 50px; background: #0a0a0a; color: #ff0000;'><h1>[-] ACCESS DENIED</h1><p>Invalid credentials</p><a href='/admin' style='color: #fbbf24;'>Try Again</a></body></html>";
                response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
            }

        } else if (method == "GET" && path == "/robots.txt") {
            string content = "User-agent: *\nDisallow: /admin\nDisallow: /secret-flag-2\nDisallow: /.git\n\n# Web Crawler Rules";
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;

        } else if (method == "GET" && path == "/secret-flag-2") {
            string content = "<html><body style='font-family: monospace; text-align: center; padding: 50px; background: #1a0f2e; color: #e8e8e8;'><h1 style='color: #10b981;'>[+] FLAG CAPTURED!</h1><hr><h2 style='color: #fbbf24; margin-top: 30px;'>FLAG 2: {DIR_ENUM_PRO_99}</h2><p style='margin-top: 20px;'>You found the hidden directory! Copy this flag and submit it.</p></body></html>";
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;

        } else if (method == "GET" && path.find("/style.css") != string::npos) {
            response = serveFile("style.css");

        } else if (method == "GET" && (path == "/" || path == "/index.html")) {
            response = serveFile("index.html");

        } else {
            string content = "<html><body style='text-align: center; padding: 50px; background: #1a0f2e; color: white;'><h1>404 - Page Not Found</h1><a href='/' style='color: #fbbf24;'>← Go Home</a></body></html>";
            response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: " + to_string(content.size()) + "\r\n\r\n" + content;
        }

        send(new_socket, response.c_str(), response.size(), 0);
        close(new_socket);
    }
    return 0;
}
