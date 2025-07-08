// Dummy blockchain log and alert data
const blockchainLogs = [
  { batchId: "BATCH2025-001", status: "✅ Genuine", manufacturer: "MedIndia", timestamp: "2025-07-08 11:32" },
  { batchId: "BATCH2025-002", status: "✅ Genuine", manufacturer: "PharmaCare", timestamp: "2025-07-08 12:10" },
  { batchId: "BATCH2025-005", status: "❌ Suspicious", manufacturer: "HealMore", timestamp: "2025-07-08 13:05" }
];

const aiAlerts = [
  { batchId: "BATCH2025-005", issue: "Tampered route - Distributor missing" },
  { batchId: "BATCH2025-009", issue: "Timestamp conflict - Mismatch in origin" }
];

// Display blockchain logs
const logList = document.getElementById("logList");
blockchainLogs.forEach(log => {
  const item = document.createElement("li");
  item.textContent = `${log.batchId} | ${log.status} | ${log.manufacturer} | ${log.timestamp}`;
  logList.appendChild(item);
});

// Display AI alerts
const alertList = document.getElementById("alertList");
aiAlerts.forEach(alert => {
  const item = document.createElement("li");
  item.textContent = `${alert.batchId}: ${alert.issue}`;
  item.style.backgroundColor = "#ffebee";
  item.style.borderLeft = "5px solid #c62828";
  alertList.appendChild(item);
});

// Verify function
function verifyBatch() {
  const input = document.getElementById("batchInput").value.trim().toUpperCase();
  const resultBox = document.getElementById("resultBox");

  const found = blockchainLogs.find(log => log.batchId === input);
  if (found) {
    resultBox.style.color = found.status.includes("❌") ? "red" : "green";
    resultBox.textContent = `Batch ${found.batchId} is ${found.status} (${found.manufacturer})`;
  } else {
    resultBox.style.color = "gray";
    resultBox.textContent = "Batch not found. Please check the ID or try again.";
  }
}

// Logout
function logout() {
  window.location.href = "index.html"; // redirect to login
}
