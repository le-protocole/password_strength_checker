const passwordInput = document.getElementById("password");
const toggleBtn = document.getElementById("toggleVisibility");

const results = document.getElementById("results");
const empty = document.getElementById("empty");

const strengthBar = document.getElementById("strengthBar");
const strengthLabel = document.getElementById("strengthLabel");
const strengthScore = document.getElementById("strengthScore");

const lengthValue = document.getElementById("lengthValue");
const entropyValue = document.getElementById("entropyValue");

const checks = {
  upper: document.getElementById("upper"),
  lower: document.getElementById("lower"),
  number: document.getElementById("number"),
  special: document.getElementById("special"),
  length: document.getElementById("lengthCheck")
};

const recommendations = document.getElementById("recommendations");

toggleBtn.onclick = () => {
  passwordInput.type =
    passwordInput.type === "password" ? "text" : "password";
};

passwordInput.addEventListener("input", () => {
  const pwd = passwordInput.value;

  if (!pwd) {
    results.classList.add("hidden");
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";
  results.classList.remove("hidden");

  const length = pwd.length;
  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasNumber = /\d/.test(pwd);
  const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

  let score = 0;
  if (length >= 8) score += 20;
  if (hasUpper) score += 20;
  if (hasLower) score += 20;
  if (hasNumber) score += 20;
  if (hasSpecial) score += 20;

  // Strength bar
  strengthBar.style.width = score + "%";
  strengthBar.style.background =
    score < 40 ? "#ef4444" :
    score < 70 ? "#f59e0b" :
    "#22c55e";

  strengthLabel.textContent =
    score < 40 ? "Weak" :
    score < 70 ? "Medium" :
    "Strong";

  strengthScore.textContent = `${score} / 100`;

  // Metrics
  lengthValue.textContent = length;
  entropyValue.textContent = Math.round(length * 4) + " bits";

  // Checks
  updateCheck(checks.upper, hasUpper);
  updateCheck(checks.lower, hasLower);
  updateCheck(checks.number, hasNumber);
  updateCheck(checks.special, hasSpecial);
  updateCheck(checks.length, length >= 8);

  // Recommendations
  recommendations.innerHTML = "";
  if (length < 12) addRec("Use at least 12 characters");
  if (!hasUpper) addRec("Add uppercase letters");
  if (!hasLower) addRec("Add lowercase letters");
  if (!hasNumber) addRec("Include numbers");
  if (!hasSpecial) addRec("Include special characters");
});

function updateCheck(el, valid) {
  el.textContent = valid ? "✓" : "✗";
  el.className = "icon " + (valid ? "valid" : "invalid");
}

function addRec(text) {
  const li = document.createElement("li");
  li.textContent = "• " + text;
  recommendations.appendChild(li);
}
