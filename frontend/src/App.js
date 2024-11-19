import React, { useState, useEffect } from "react";
import axios from "axios";
import { TextField, Button, Typography, Box, Paper, Select, MenuItem, Divider } from "@mui/material";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";
import { Bar } from "react-chartjs-2";

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

function App() {
  const [riskFactors, setRiskFactors] = useState("");
  const [result, setResult] = useState(null);
  const [complianceType, setComplianceType] = useState("ISO 27001");
  const [complianceResult, setComplianceResult] = useState(null);

  const [plainText, setPlainText] = useState("");
  const [encryptedText, setEncryptedText] = useState("");
  const [decryptedText, setDecryptedText] = useState("");

  const [scanTarget, setScanTarget] = useState("");
  const [scanResults, setScanResults] = useState(null);

  const [history, setHistory] = useState([]);
  
   // Authentication states
   const [username, setUsername] = useState("");
   const [password, setPassword] = useState("");
   const [token, setToken] = useState(localStorage.getItem("token") || null);

   // Track user role
   const [role, setRole] = useState("");

   
  // Fetch History
  const fetchHistory = async () => {
    if (!token) return; // Prevent fetch if no token is available
    try {
      const response = await axios.get("http://127.0.0.1:5000/history", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      setHistory(response.data);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  useEffect(() => {
    if (token) {
      fetchHistory();
    }
  }, [token]);

  // Handle Risk Assessment
  const handleRiskAssessment = async () => {
    const factors = riskFactors.split(",").map((factor) => ({
      name: factor.trim(),
      severity: Math.floor(Math.random() * 10) + 1, // Random severity for demo
    }));

    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/assess-risk",
        { risk_factors: factors },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setResult(response.data);
    } catch (error) {
      console.error("Error:", error);
    }
  };

  // Handle Compliance Check
  const handleComplianceCheck = async () => {
    const factors = riskFactors.split(",").map((factor) => ({
      name: factor.trim(),
      severity: Math.floor(Math.random() * 10) + 1,
    }));

    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/check-compliance",
        { compliance_type: complianceType, risk_factors: factors },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setComplianceResult(response.data);
    } catch (error) {
      console.error("Error:", error);
    }
  };

  // Handle Encryption
  const handleEncrypt = async () => {
    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/encrypt",
        { text: plainText },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setEncryptedText(response.data.encrypted_text);
    } catch (error) {
      console.error("Error encrypting text:", error);
    }
  };

  // Handle Decryption
  const handleDecrypt = async () => {
    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/decrypt",
        { encrypted_text: encryptedText },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setDecryptedText(response.data.decrypted_text);
    } catch (error) {
      console.error("Error decrypting text:", error);
    }
  };

  // Handle Network Scan
  const handleNetworkScan = async () => {
    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/scan-network",
        { target: scanTarget },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setScanResults(response.data.results);
    } catch (error) {
      console.error("Error scanning network:", error);
    }
  };

   // Handle Signup
   const handleSignup = async () => {
    try {
      await axios.post("http://127.0.0.1:5000/signup", { username, password });
      alert("Signup successful. Please log in.");
    } catch (error) {
      console.error("Signup error:", error);
    }
  };

  // Handle Login
  const handleLogin = async () => {
    try {
      const response = await axios.post("http://127.0.0.1:5000/login", { username, password });
      const accessToken = response.data.access_token;
      const decoded = JSON.parse(atob(accessToken.split(".")[1])); // Decode JWT payload
      setRole(decoded.role);
      setToken(accessToken);
      localStorage.setItem("token", accessToken);
    } catch (error) {
      console.error("Login error:", error);
    }
  };
  

  // Handle Logout
  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem("token");
    setHistory([]); // Clear history on logout
  };


  return (
    <Box sx={{ padding: "20px", fontFamily: "Arial" }}>
    {!token ? (
      <Box>
        <TextField 
          label="Role" 
          onChange={(e) => setRole(e.target.value)} 
          sx={{ marginBottom: "10px" }} 
        /> {/* During signup */}
        <Typography variant="h5" gutterBottom>
          Authentication
        </Typography>
        <TextField
          label="Username"
          variant="outlined"
          fullWidth
          sx={{ marginBottom: "10px" }}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextField
          label="Password"
          variant="outlined"
          type="password"
          fullWidth
          sx={{ marginBottom: "10px" }}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button
          variant="contained"
          color="primary"
          sx={{ marginRight: "10px" }}
          onClick={handleLogin}
        >
          Login
        </Button>
        <Button variant="outlined" color="secondary" onClick={handleSignup}>
          Signup
        </Button>
      </Box>
    ) : role === "admin" ? (
      <Typography>Welcome, Admin!</Typography>
    ) : (
      <Typography>Welcome, User!</Typography>
    )}
    {token && (
      <Box>
        <Typography variant="h5" gutterBottom>
          Welcome, {username || "User"}!
        </Typography>
        <Button variant="contained" color="error" onClick={handleLogout}>
          Logout
        </Button>
  
          {/* Risk Assessment Section */}
          <Typography variant="h4" gutterBottom sx={{ marginTop: "20px" }}>
            Risk Assessment Framework
          </Typography>
          <TextField
            label="Enter Risk Factors (comma-separated)"
            variant="outlined"
            fullWidth
            onChange={(e) => setRiskFactors(e.target.value)}
          />
          <Select
            value={complianceType}
            onChange={(e) => setComplianceType(e.target.value)}
            fullWidth
            sx={{ marginTop: "10px" }}
          >
            <MenuItem value="ISO 27001">ISO 27001</MenuItem>
            <MenuItem value="HIPAA">HIPAA</MenuItem>
            <MenuItem value="PCI DSS">PCI DSS</MenuItem>
          </Select>
          <Button
            variant="contained"
            color="primary"
            sx={{ marginTop: "10px" }}
            onClick={handleRiskAssessment}
          >
            Assess Risk
          </Button>
          <Button
            variant="outlined"
            color="secondary"
            sx={{ marginTop: "10px", marginLeft: "10px" }}
            onClick={handleComplianceCheck}
          >
            Check Compliance
          </Button>
  
          {/* Risk Assessment Results */}
          {result && (
            <Paper elevation={3} sx={{ marginTop: "20px", padding: "20px" }}>
              <Typography variant="h5">Assessment Results</Typography>
              <Typography>Risk Score: {result.risk_score}</Typography>
              <Typography>Recommendations:</Typography>
              <ul>
                {result.recommendations.map((rec, index) => (
                  <li key={index}>{rec}</li>
                ))}
              </ul>
              <Bar
                data={{
                  labels: result.recommendations.map((_, index) => `Risk ${index + 1}`),
                  datasets: [
                    {
                      label: "Severity Levels",
                      data: result.recommendations.map(() =>
                        Math.floor(Math.random() * 10) + 1
                      ),
                      backgroundColor: "rgba(75,192,192,0.6)",
                    },
                  ],
                }}
                options={{
                  responsive: true,
                  plugins: {
                    legend: { display: true },
                  },
                }}
              />
            </Paper>
          )}
  
          {/* Compliance Results */}
          {complianceResult && (
            <Paper elevation={3} sx={{ marginTop: "20px", padding: "20px" }}>
              <Typography variant="h5">Compliance Results</Typography>
              <Typography>Compliance Type: {complianceResult.compliance_type}</Typography>
              <Typography>Non-Compliant Factors:</Typography>
              <ul>
                {complianceResult.non_compliant_factors.map((factor, index) => (
                  <li key={index}>{factor}</li>
                ))}
              </ul>
            </Paper>
          )}
  
          {/* Encryption/Decryption Section */}
          <Divider sx={{ marginY: "20px" }} />
          <Typography variant="h4" gutterBottom>
            Real-Time Encryption/Decryption
          </Typography>
          <TextField
            label="Plain Text"
            variant="outlined"
            fullWidth
            sx={{ marginY: "10px" }}
            onChange={(e) => setPlainText(e.target.value)}
          />
          <Button
            variant="contained"
            color="primary"
            sx={{ marginRight: "10px" }}
            onClick={handleEncrypt}
          >
            Encrypt
          </Button>
          <Typography variant="body1" sx={{ marginTop: "10px" }}>
            Encrypted Text: {encryptedText}
          </Typography>
          <TextField
            label="Encrypted Text"
            variant="outlined"
            fullWidth
            sx={{ marginY: "10px" }}
            value={encryptedText}
            onChange={(e) => setEncryptedText(e.target.value)}
          />
          <Button variant="outlined" color="secondary" onClick={handleDecrypt}>
            Decrypt
          </Button>
          <Typography variant="body1" sx={{ marginTop: "10px" }}>
            Decrypted Text: {decryptedText}
          </Typography>
  
          {/* Network Scanning Section */}
          <Divider sx={{ marginY: "20px" }} />
          <Typography variant="h4" gutterBottom>
            Network Vulnerability Scanning
          </Typography>
          <TextField
            label="Target IP or Range"
            variant="outlined"
            fullWidth
            sx={{ marginY: "10px" }}
            onChange={(e) => setScanTarget(e.target.value)}
          />
          <Button variant="contained" color="primary" onClick={handleNetworkScan}>
            Scan Network
          </Button>
          {scanResults && (
            <Paper elevation={3} sx={{ marginTop: "20px", padding: "20px" }}>
              <Typography variant="h5">Scan Results</Typography>
              {scanResults.map((host, index) => (
                <Box key={index} sx={{ marginBottom: "20px" }}>
                  <Typography variant="h6">Host: {host.host}</Typography>
                  <Typography>Status: {host.status}</Typography>
                  <Typography>Open Ports:</Typography>
                  <ul>
                    {host.ports.map((port, portIndex) => (
                      <li key={portIndex}>
                        Port: {port.port}, Service: {port.service}, State: {port.state}
                      </li>
                    ))}
                  </ul>
                </Box>
              ))}
            </Paper>
          )}
  
          {/* History Section */}
          <Divider sx={{ marginY: "20px" }} />
          <Typography variant="h4" gutterBottom>
            History
          </Typography>
          {history.length > 0 ? (
            <Paper elevation={3} sx={{ marginTop: "20px", padding: "20px" }}>
              <ul>
                {history.map((item, index) => (
                  <li key={index}>
                    {item.type === "assessment" ? (
                      `Risk Score: ${item.risk_score}, Date: ${item.date}`
                    ) : (
                      `Scan Target: ${item.target}, Date: ${item.date}`
                    )}
                  </li>
                ))}
              </ul>
            </Paper>
          ) : (
            <Typography>No history available.</Typography>
          )}
        </Box>
      )}
    </Box>
  );  
}

export default App;

