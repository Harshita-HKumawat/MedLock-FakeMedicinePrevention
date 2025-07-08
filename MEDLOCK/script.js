document.getElementById('loginForm').addEventListener('submit', function(e) {
  e.preventDefault(); // prevent form from submitting

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  const message = document.getElementById('message');

  // Hardcoded credentials (demo purpose)
  const demoUser = 'admin';
  const demoPass = 'medlock123';

  // ✅ Login Success Block (Insert this here!)
  if (username === demoUser && password === demoPass) {
    message.style.color = 'green';
    message.textContent = 'Login successful! Redirecting...';

    setTimeout(() => {
      window.location.href = 'welcome.html';  // Redirects to welcome page
    }, 1500);
  } else {
    message.style.color = 'red';
    message.textContent = 'Invalid username or password.';
  }
});
