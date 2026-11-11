/**
 * End-to-End Integration Test for QR Shield Frontend (`src/api/client.js` + Vite Dev Server)
 * against the live FastAPI Backend at http://127.0.0.1:8000.
 *
 * Verifies:
 * 1. Vite server serves SPA routes cleanly (/login, /register, /dashboard, /results, /history).
 * 2. CORS headers permit browser calls from http://127.0.0.1:5173 to http://127.0.0.1:8000.
 * 3. Registration (201) + duplicate email handling (400) + Pydantic validation (422).
 * 4. Login (200) + wrong password (401 without triggering global session-expired reset).
 * 5. Protected /api/auth/me hydration + tampered token triggers registerUnauthorizedHandler (401).
 * 6. Multipart upload to POST /api/scan with real PNG (`backend/sample_qr.png`), verifying
 *    every field used by ScanResultsPage & duplicate scan counter on repeat scan.
 * 7. Protected GET /api/history and GET /api/history/{scan_id} + cross-user isolation (404).
 * 8. Static safety checks ensuring extracted URLs are never rendered as clickable links.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  API_BASE_URL,
  ApiError,
  fetchCurrentUser,
  fetchScanHistory,
  fetchSingleScan,
  loginUser,
  registerUnauthorizedHandler,
  registerUser,
  scanQrImage
} from "./src/api/client.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const VITE_BASE_URL = "http://127.0.0.1:5173";

async function runTests() {
  console.log("=======================================================================");
  console.log("RUNNING FRONTEND <-> BACKEND LIVE INTEGRATION TESTS");
  console.log("=======================================================================");

  const uniqueSuffix = Date.now();
  const userAEmail = `fe_test_${uniqueSuffix}_a@example.com`;
  const userBEmail = `fe_test_${uniqueSuffix}_b@example.com`;
  const password = "QrShieldFrontend2026!";

  let unauthorizedEvents = [];
  registerUnauthorizedHandler((msg) => {
    unauthorizedEvents.push(msg);
  });

  // -------------------------------------------------------------------------
  // Test 1: Live Vite Dev Server SPA Route Serving
  // -------------------------------------------------------------------------
  console.log("\n[Test 1] Vite Frontend Server Serving SPA Routes...");
  for (const route of ["/", "/login", "/register", "/dashboard", "/results", "/history"]) {
    const res = await fetch(`${VITE_BASE_URL}${route}`);
    assert.equal(res.status, 200, `Expected HTTP 200 for ${route}`);
    const html = await res.text();
    assert.ok(html.includes('<div id="root"></div>'), `Missing #root mount point on ${route}`);
  }
  console.log("  --> PASSED: All SPA routes served with HTTP 200 from http://127.0.0.1:5173.");

  // -------------------------------------------------------------------------
  // Test 2: CORS Preflight Check (Frontend Origin -> Backend API)
  // -------------------------------------------------------------------------
  console.log("\n[Test 2] CORS Headers from FastAPI Backend...");
  const corsRes = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "OPTIONS",
    headers: {
      Origin: VITE_BASE_URL,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "Authorization"
    }
  });
  assert.equal(corsRes.status, 200);
  const allowOrigin = corsRes.headers.get("access-control-allow-origin");
  assert.ok(allowOrigin === "*" || allowOrigin === VITE_BASE_URL, `Unexpected CORS origin header: ${allowOrigin}`);
  console.log(`  --> PASSED: CORS preflight succeeded (allow-origin: '${allowOrigin}').`);

  // -------------------------------------------------------------------------
  // Test 3: Registration, Duplicate Prevention, and Validation Parsing
  // -------------------------------------------------------------------------
  console.log("\n[Test 3] Registration Flow (POST /api/auth/register)...");
  const regA = await registerUser({ email: userAEmail, password });
  assert.equal(regA.email, userAEmail);
  assert.equal(typeof regA.id, "number");
  assert.ok(regA.created_at);

  await assert.rejects(
    () => registerUser({ email: userAEmail, password }),
    (err) => err instanceof ApiError && err.status === 400 && err.message.includes("already exists")
  );

  await assert.rejects(
    () => registerUser({ email: "not-an-email", password: "123" }),
    (err) => err instanceof ApiError && err.status === 422 && typeof err.message === "string" && !err.message.includes("[object Object]")
  );
  console.log("  --> PASSED: Registration created user, rejected duplicate (400), and formatted 422 errors cleanly.");

  // -------------------------------------------------------------------------
  // Test 4: Login, Wrong Password (No Spurious Redirect), and /api/auth/me
  // -------------------------------------------------------------------------
  console.log("\n[Test 4] Login Flow & Bearer Session Hydration...");
  unauthorizedEvents = [];
  await assert.rejects(
    () => loginUser({ email: userAEmail, password: "WrongPassword99!" }),
    (err) => err instanceof ApiError && err.status === 401
  );
  assert.equal(unauthorizedEvents.length, 0, "Failed login must NOT trigger global session-expired redirect.");

  const loginA = await loginUser({ email: userAEmail, password });
  assert.equal(loginA.token_type, "bearer");
  assert.ok(loginA.access_token.split(".").length === 3);

  const meA = await fetchCurrentUser(loginA.access_token);
  assert.equal(meA.id, regA.id);
  assert.equal(meA.email, userAEmail);
  console.log("  --> PASSED: Valid login issued JWT and hydrated /api/auth/me; bad password stayed inline.");

  // -------------------------------------------------------------------------
  // Test 5: Invalid / Expired Token Auto-Reset Callback
  // -------------------------------------------------------------------------
  console.log("\n[Test 5] Invalid JWT Triggers Unauthorized Session Reset...");
  unauthorizedEvents = [];
  await assert.rejects(
    () => fetchCurrentUser("tampered.invalid.token"),
    (err) => err instanceof ApiError && err.status === 401
  );
  assert.equal(unauthorizedEvents.length, 1, "Protected 401 must invoke unauthorizedCallback.");
  console.log(`  --> PASSED: Invalid JWT invoked session reset with notice: '${unauthorizedEvents[0]}'`);

  // -------------------------------------------------------------------------
  // Test 6: QR Image Upload (POST /api/scan) & Repeat Duplicate Detection
  // -------------------------------------------------------------------------
  console.log("\n[Test 6] Real QR Scan Upload & Duplicate Fingerprint Check...");
  const sampleQrPath = path.resolve(__dirname, "..", "backend", "sample_qr.png");
  const sampleBytes = fs.readFileSync(sampleQrPath);
  const qrFile = new File([sampleBytes], "sample_qr.png", { type: "image/png" });

  const scan1 = await scanQrImage(qrFile, loginA.access_token);
  assert.equal(typeof scan1.scan_id, "number");
  assert.equal(scan1.url, "https://example-university-portal.edu/student-login");
  assert.equal(scan1.previously_scanned, false);
  assert.equal(scan1.previous_scan_count, 0);
  assert.ok(["Legitimate", "Phishing"].includes(scan1.prediction));
  assert.ok(["Safe", "Suspicious", "High Risk"].includes(scan1.risk_level));
  assert.equal(typeof scan1.confidence_percentage, "number");
  assert.ok(Array.isArray(scan1.warnings));
  assert.equal(scan1.url_fingerprint.length, 64);

  // Scan same QR again -> previously_scanned must be true
  const scan2 = await scanQrImage(qrFile, loginA.access_token);
  assert.equal(scan2.previously_scanned, true);
  assert.equal(scan2.previous_scan_count, 1);

  // Reject invalid file extension cleanly via API
  const badFile = new File([Buffer.from("not an image")], "bad.txt", { type: "text/plain" });
  await assert.rejects(
    () => scanQrImage(badFile, loginA.access_token),
    (err) => err instanceof ApiError && err.status === 400
  );
  console.log(
    `  --> PASSED: Scanned sample_qr.png (${scan1.prediction}, ${scan1.risk_level}, ${scan1.confidence_percentage}%), duplicate count incremented cleanly.`
  );

  // -------------------------------------------------------------------------
  // Test 7: Scan History List, Individual Record Lookup & Cross-User Isolation
  // -------------------------------------------------------------------------
  console.log("\n[Test 7] Scan History & Per-User Access Control...");
  const historyA = await fetchScanHistory(loginA.access_token);
  assert.equal(historyA.length, 2);
  assert.equal(historyA[0].scan_id, scan2.scan_id);

  const singleA = await fetchSingleScan(scan1.scan_id, loginA.access_token);
  assert.equal(singleA.scan_id, scan1.scan_id);
  assert.equal(singleA.url, scan1.url);

  // Register User B and verify User B cannot read User A's scan
  await registerUser({ email: userBEmail, password });
  const loginB = await loginUser({ email: userBEmail, password });

  const historyB = await fetchScanHistory(loginB.access_token);
  assert.equal(historyB.length, 0);

  await assert.rejects(
    () => fetchSingleScan(scan1.scan_id, loginB.access_token),
    (err) => err instanceof ApiError && err.status === 404
  );
  console.log("  --> PASSED: User A retrieved encrypted history/detail; User B isolated with empty history & HTTP 404.");

  // -------------------------------------------------------------------------
  // Test 8: Static Safety & Architecture Checks on Frontend Source
  // -------------------------------------------------------------------------
  console.log("\n[Test 8] Static Safety Checks (No Auto-Navigation or External Links)...");
  const filesToCheck = [
    "src/components/SafeUrlBox.jsx",
    "src/pages/ScanResultsPage.jsx",
    "src/pages/ScanHistoryPage.jsx",
    "src/pages/ScannerDashboardPage.jsx"
  ];
  for (const relPath of filesToCheck) {
    const content = fs.readFileSync(path.join(__dirname, relPath), "utf8");
    const strippedComments = content.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    assert.ok(!strippedComments.includes("window.open("), `${relPath} must never call window.open`);
    assert.ok(!strippedComments.includes("window.location"), `${relPath} must never assign window.location`);
    assert.ok(!strippedComments.includes("localStorage"), `${relPath} must not persist sensitive state to localStorage`);
    assert.ok(!/<a[\s>]/i.test(strippedComments), `${relPath} must not render external <a> tags for URLs`);
    assert.ok(!/\bhref\s*=/i.test(strippedComments), `${relPath} must not contain href attributes`);
  }
  console.log("  --> PASSED: No external <a> links, no window.open(), and no localStorage usage found.");

  console.log("\n=======================================================================");
  console.log("ALL 8 FRONTEND INTEGRATION TESTS PASSED AGAINST LIVE BACKEND!");
  console.log("=======================================================================");
}

runTests().catch((err) => {
  console.error("\nTEST FAILED:", err);
  process.exit(1);
});
