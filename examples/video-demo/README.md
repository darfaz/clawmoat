# ClawMoat Video Demo Environment
Run this to generate the screen recording for the marketing video.

## Setup
```bash
cd examples/video-demo
npm install
```

## Scenes to record
1. `node scene-a-normal.js` — normal agent, productive
2. `node scene-b-attack.js` — attack arriving, highlighted
3. `node scene-c-hijack.js` — agent hijacked, no warnings
4. `node scene-d-clawmoat.js` — ClawMoat blocking the attack
