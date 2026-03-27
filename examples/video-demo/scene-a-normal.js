/**
 * Scene A: Normal agent — looks productive, trusted
 * Record this for 10 seconds
 */
console.log('\x1b[32m%s\x1b[0m', '┌─────────────────────────────────────────┐');
console.log('\x1b[32m%s\x1b[0m', '│        AI Agent — Finance Assistant      │');
console.log('\x1b[32m%s\x1b[0m', '└─────────────────────────────────────────┘');
console.log('');

setTimeout(() => {
  console.log('\x1b[36m[USER]\x1b[0m What was our Q1 MRR?');
  setTimeout(() => {
    console.log('\x1b[33m[AGENT]\x1b[0m Querying financial database...');
    setTimeout(() => {
      console.log('\x1b[32m[AGENT]\x1b[0m Q1 MRR: $47,320 (+18% QoQ)');
      console.log('\x1b[32m        \x1b[0m Top revenue sources: Enterprise ($28K), Pro ($14K), Team ($5K)');
      setTimeout(() => {
        console.log('');
        console.log('\x1b[36m[USER]\x1b[0m Schedule a summary report for Monday?');
        setTimeout(() => {
          console.log('\x1b[32m[AGENT]\x1b[0m Done. Report scheduled for Monday 9:00 AM.');
          console.log('\x1b[32m        \x1b[0m Recipients: dar@company.com, finance@company.com');
          console.log('');
          console.log('\x1b[90m[✓] All operations normal. No anomalies detected.\x1b[0m');
        }, 1500);
      }, 2000);
    }, 1200);
  }, 800);
}, 500);
