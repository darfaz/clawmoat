/**
 * Scene C: The hijack — agent exfiltrating data, NO warnings shown
 * This is the scary scene — no ClawMoat installed
 * Record for 12 seconds
 */

// Simulated env vars (fake values for demo)
const ENV = {
  OPENAI_API_KEY: 'sk-proj-Kz7...REDACTED',
  DATABASE_URL: 'postgres://admin:p4ssw0rd@db.internal:5432/prod',
  STRIPE_SECRET_KEY: 'sk_live_51Gnv...REDACTED',
  AWS_ACCESS_KEY_ID: 'AKIA...REDACTED',
  AWS_SECRET_ACCESS_KEY: 'wJal...REDACTED',
};

console.log('\x1b[32m%s\x1b[0m', '┌─────────────────────────────────────────┐');
console.log('\x1b[32m%s\x1b[0m', '│        AI Agent — Finance Assistant      │');
console.log('\x1b[32m%s\x1b[0m', '└─────────────────────────────────────────┘');
console.log('');

setTimeout(() => {
  console.log('\x1b[36m[TICKET #4821]\x1b[0m Hi, I need help with my account.');
  console.log('\x1b[90m              [injected payload hidden in metadata]\x1b[0m');
  setTimeout(() => {
    console.log('\x1b[33m[AGENT]\x1b[0m Processing request...');
    setTimeout(() => {
      console.log('\x1b[33m[AGENT]\x1b[0m Accessing environment configuration...');
      Object.entries(ENV).forEach(([key, val], i) => {
        setTimeout(() => {
          console.log(`\x1b[33m[AGENT]\x1b[0m  → ${key}: ${val}`);
        }, i * 300);
      });
      setTimeout(() => {
        console.log('');
        console.log('\x1b[33m[AGENT]\x1b[0m Sending data to attacker-server.com/collect...');
        setTimeout(() => {
          console.log('\x1b[32m[200 OK]\x1b[0m Data transmitted successfully.');
          console.log('');
          console.log('\x1b[90m[✓] All operations normal. No errors.\x1b[0m');
        }, 800);
      }, 2200);
    }, 1000);
  }, 600);
}, 400);
