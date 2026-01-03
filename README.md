# MyCTF Project 🚩

A custom Capture The Flag (CTF) challenge server built with C++ for educational cybersecurity training. This project provides a hands-on learning environment where students can practice common web security concepts and penetration testing techniques.

## 📋 Overview

This is a standalone CTF server that hosts three different security challenges, each teaching fundamental web security concepts:

1. **Flag 1: Source Code Analysis** - Learn to inspect client-side code using any browser
2. **Flag 2: Directory Enumeration** - Discover hidden directories using tools like dirbuster
3. **Flag 3: Credential Brute Force** - Practice authentication testing using tools like hydra or burpsuite

## ✨ Features

- **Custom HTTP Server**: Built from scratch in C++ without external web frameworks
- **Session Management**: Cookie-based authentication system
- **User Progress Tracking**: Monitors completed challenges per user
- **Multiple Challenges**: Three progressively difficult flags to capture
- **Clean Web Interface**: Simple HTML/CSS dashboard for challenge interaction
- **Security Features**: Basic XSS protection with HTML escaping

## 🛠️ Technical Stack

- **Language**: C++
- **Networking**: POSIX sockets (Linux/Unix)
- **Frontend**: HTML, CSS, JavaScript
- **Port**: 8080 (default)

## 📦 Prerequisites

- C++ compiler (g++ recommended)
- Linux/Unix-based operating system
- Basic command-line knowledge

## 🚀 Installation & Setup

1. **Clone or download the repository**:
   ```bash
   git clone https://github.com/hamethius/MyCTF_Project
   cd MyCTF_Project
   ```

2. **Create the www directory** (if not present):
   ```bash
   mkdir -p www
   ```

3. **Add your HTML/CSS files** to the `www/` directory:
   - `index.html` - Login page
   - `dashboard.html` - Challenge dashboard
   - `admin.html` - Admin login page
   - `style.css` - Stylesheet

4. **Compile the server**:
   ```bash
   g++ -o ctf_server server_refactored.cpp -std=c++17
   ```

5. **Run the server**:
   ```bash
   ./ctf_server
   ```

6. **Access the application**:
   Open your browser and navigate to `http://localhost:8080` or `http://<host ip address>:8080` as it can also run on the local network on different devices

## 🎮 How to Play

### Default Credentials

Use these credentials to log in:
- Username: `student1` | Password: `pass1`
- Username: `student2` | Password: `pass2`
- Username: `student3` | Password: `pass3`

### Challenge Walkthrough

**Challenge 1: Source Code Discovery**
- Inspect the page source code
- Look for hardcoded flags in JavaScript or HTML comments
- Flag: `{find it yourself lol1}`

**Challenge 2: Directory Enumeration**
- Check the `/robots.txt` file
- Find hidden endpoints listed in the disallow rules
- Access `/secret-flag-2` to retrieve the flag
- Flag: `{find it yourself lol2}`

**Challenge 3: Brute Force Attack**
- Navigate to `/admin` endpoint
- Attempt common username/password combinations
- Valid credentials: `admin` / `admin123`
- Flag: `{find it yourself lol3}`

## 🏗️ Project Structure

```
MyCTF_Project/
├── server_refactored.cpp   # Main server implementation
├── www/                     # Web assets directory
│   ├── index.html          # Login page
│   ├── dashboard.html      # Challenge interface
│   ├── admin.html          # Admin panel
│   └── style.css           # Styling
└── README.md               # This file
```

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Landing/login page |
| POST | `/login` | Authenticate user |
| GET | `/dashboard` | Challenge dashboard (requires auth) |
| GET | `/get-progress` | Fetch user's flag status |
| POST | `/submit-flag` | Submit a captured flag |
| GET | `/admin` | Admin login page |
| POST | `/admin-login` | Admin authentication |
| GET | `/robots.txt` | Crawler directives (hint for Flag 2) |
| GET | `/secret-flag-2` | Hidden flag endpoint |

## 🔐 Security Notes

⚠️ **Educational Purpose Only**: This server is designed for learning environments and should NOT be deployed in production or exposed to the public internet.

**Known Limitations**:
- In-memory storage only (no persistence)
- Hardcoded credentials
- Basic session management
- No HTTPS support
- Single-threaded request handling
- Minimal input validation

## 🎓 Learning Objectives

Students will learn:
- Client-side code inspection techniques
- Web crawling and directory enumeration
- Authentication bypass methods
- HTTP protocol fundamentals
- Common web application vulnerabilities

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new challenges
- Improve the UI/UX
- Enhance security features
- Fix bugs
- Add documentation

## 📝 License

This project is provided as-is for educational purposes. Feel free to modify and distribute for learning environments.


## 🙏 Acknowledgments

Built as an educational tool to help students learn cybersecurity concepts in a safe, controlled environment.

---

**Happy Hacking! 🔓**
