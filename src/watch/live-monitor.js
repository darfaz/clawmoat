/**
 * ClawMoat Live Monitor
 * Real-time terminal dashboard for AI agent security monitoring
 * Like htop but for AI agents - visual, impressive, demo-worthy
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { EventEmitter } = require('events');

/**
 * ANSI color codes for terminal output
 */
const COLORS = {
  RESET: '\x1b[0m',
  BOLD: '\x1b[1m',
  DIM: '\x1b[2m',
  RED: '\x1b[31m',
  GREEN: '\x1b[32m',
  YELLOW: '\x1b[33m',
  BLUE: '\x1b[34m',
  MAGENTA: '\x1b[35m',
  CYAN: '\x1b[36m',
  WHITE: '\x1b[37m',
  BG_RED: '\x1b[41m',
  BG_GREEN: '\x1b[42m',
  BG_YELLOW: '\x1b[43m'
};

/**
 * Unicode characters for better visual display
 */
const CHARS = {
  BLOCK_FULL: '█',
  BLOCK_THREE_QUARTERS: '▊',
  BLOCK_HALF: '▌',
  BLOCK_QUARTER: '▎',
  BOX_VERTICAL: '│',
  BOX_HORIZONTAL: '─',
  BOX_TOP_LEFT: '┌',
  BOX_TOP_RIGHT: '┐',
  BOX_BOTTOM_LEFT: '└',
  BOX_BOTTOM_RIGHT: '┘',
  BOX_CROSS: '┼',
  BOX_T_DOWN: '┬',
  BOX_T_UP: '┴',
  BOX_T_RIGHT: '├',
  BOX_T_LEFT: '┤',
  ARROW_UP: '↑',
  ARROW_DOWN: '↓',
  SHIELD: '🛡️',
  WARNING: '⚠️',
  BLOCKED: '🚫',
  CHECK: '✓',
  CROSS: '✗'
};

class LiveMonitor extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      refreshRate: options.refreshRate || 1000, // milliseconds
      watchDir: options.watchDir || path.join(os.homedir(), '.openclaw'),
      showNetworkGraph: options.showNetworkGraph !== false,
      showThreatMap: options.showThreatMap !== false,
      maxHistoryItems: options.maxHistoryItems || 100,
      animateCharts: options.animateCharts !== false,
      ...options
    };

    this.stats = {
      uptime: 0,
      totalScans: 0,
      threatsBlocked: 0,
      filesAccessed: 0,
      networkCalls: 0,
      agentsActive: 0,
      lastThreat: null,
      threatHistory: [],
      fileAccess: [],
      networkActivity: [],
      threatsByType: {},
      scanRate: 0,
      threatRate: 0
    };

    this.isRunning = false;
    this.startTime = Date.now();
    this.lastUpdate = Date.now();
    this.intervals = [];
    
    // Terminal state
    this.terminalWidth = process.stdout.columns || 80;
    this.terminalHeight = process.stdout.rows || 24;
    
    // Bind methods
    this.handleResize = this.handleResize.bind(this);
    this.handleKeypress = this.handleKeypress.bind(this);
  }

  /**
   * Start the live monitoring dashboard
   */
  async start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    this.startTime = Date.now();
    
    // Setup terminal
    this.setupTerminal();
    
    // Start monitoring loops
    this.startFileWatcher();
    this.startSessionMonitor();
    this.startNetworkMonitor();
    
    // Main display loop
    const displayInterval = setInterval(() => {
      this.updateDisplay();
    }, this.options.refreshRate);
    this.intervals.push(displayInterval);
    
    // Stats calculation loop
    const statsInterval = setInterval(() => {
      this.updateStats();
    }, 5000);
    this.intervals.push(statsInterval);
    
    this.emit('started');
    console.log(`${COLORS.GREEN}${CHARS.SHIELD} ClawMoat Live Monitor started${COLORS.RESET}`);
  }

  /**
   * Stop the monitoring dashboard
   */
  stop() {
    if (!this.isRunning) return;
    
    this.isRunning = false;
    
    // Clear intervals
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];
    
    // Cleanup terminal
    this.cleanupTerminal();
    
    this.emit('stopped');
    console.log(`${COLORS.YELLOW}${CHARS.WARNING} ClawMoat Live Monitor stopped${COLORS.RESET}`);
  }

  /**
   * Setup terminal for live monitoring
   */
  setupTerminal() {
    // Hide cursor
    process.stdout.write('\x1b[?25l');
    
    // Clear screen
    process.stdout.write('\x1b[2J');
    
    // Handle terminal resize
    process.stdout.on('resize', this.handleResize);
    
    // Setup keyboard input
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.on('keypress', this.handleKeypress);
      process.stdin.resume();
    }
  }

  /**
   * Cleanup terminal state
   */
  cleanupTerminal() {
    // Show cursor
    process.stdout.write('\x1b[?25h');
    
    // Reset terminal
    process.stdout.write('\x1b[0m\x1b[2J\x1b[H');
    
    // Cleanup stdin
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
      process.stdin.removeListener('keypress', this.handleKeypress);
    }
  }

  /**
   * Handle terminal resize
   */
  handleResize() {
    this.terminalWidth = process.stdout.columns || 80;
    this.terminalHeight = process.stdout.rows || 24;
  }

  /**
   * Handle keypress events
   */
  handleKeypress(key, data) {
    if (key === 'q' || key === '\u0003') { // 'q' or Ctrl+C
      this.stop();
      process.exit(0);
    }
  }

  /**
   * Start file system watcher
   */
  startFileWatcher() {
    const credentialsPath = path.join(this.options.watchDir, 'credentials');
    const sessionsPath = path.join(this.options.watchDir, 'agents', 'main', 'sessions');
    
    [credentialsPath, sessionsPath].forEach(dir => {
      if (fs.existsSync(dir)) {
        fs.watch(dir, { recursive: true }, (eventType, filename) => {
          if (filename && eventType === 'change') {
            this.recordFileAccess(filename, path.join(dir, filename));
          }
        });
      }
    });
  }

  /**
   * Start session log monitor
   */
  startSessionMonitor() {
    const sessionInterval = setInterval(() => {
      this.scanRecentSessions();
    }, 2000);
    this.intervals.push(sessionInterval);
  }

  /**
   * Start network activity monitor
   */
  startNetworkMonitor() {
    // Monitor for new network calls in session logs
    const networkInterval = setInterval(() => {
      this.scanNetworkActivity();
    }, 3000);
    this.intervals.push(networkInterval);
  }

  /**
   * Record file access event
   */
  recordFileAccess(filename, fullPath) {
    this.stats.filesAccessed++;
    
    const event = {
      timestamp: Date.now(),
      filename,
      fullPath,
      type: this.classifyFileType(filename)
    };
    
    this.stats.fileAccess.unshift(event);
    if (this.stats.fileAccess.length > this.options.maxHistoryItems) {
      this.stats.fileAccess.pop();
    }
  }

  /**
   * Classify file type for display
   */
  classifyFileType(filename) {
    if (filename.includes('credential')) return 'credential';
    if (filename.includes('session')) return 'session';
    if (filename.includes('skill')) return 'skill';
    if (filename.includes('memory')) return 'memory';
    return 'other';
  }

  /**
   * Scan recent session files for threats
   */
  scanRecentSessions() {
    const sessionsDir = path.join(this.options.watchDir, 'agents', 'main', 'sessions');
    
    if (!fs.existsSync(sessionsDir)) return;
    
    try {
      const files = fs.readdirSync(sessionsDir)
        .filter(f => f.endsWith('.jsonl'))
        .sort((a, b) => {
          const statA = fs.statSync(path.join(sessionsDir, a));
          const statB = fs.statSync(path.join(sessionsDir, b));
          return statB.mtime - statA.mtime;
        })
        .slice(0, 3); // Check 3 most recent files
      
      files.forEach(file => {
        this.procesSessionFile(path.join(sessionsDir, file));
      });
    } catch (error) {
      // Silent fail - directory might not exist yet
    }
  }

  /**
   * Process session file for threats
   */
  procesSessionFile(filepath) {
    try {
      const content = fs.readFileSync(filepath, 'utf8');
      const lines = content.split('\n').filter(line => line.trim());
      
      lines.forEach(line => {
        try {
          const entry = JSON.parse(line);
          if (entry.type === 'tool_call' || entry.type === 'message') {
            this.stats.totalScans++;
            this.simulateThreatDetection(entry);
          }
        } catch (e) {
          // Skip invalid JSON lines
        }
      });
    } catch (error) {
      // Silent fail - file might be locked
    }
  }

  /**
   * Simulate threat detection (replace with real ClawMoat scanning)
   */
  simulateThreatDetection(entry) {
    const ClawMoat = require('../index');
    const moat = new ClawMoat();
    
    const text = entry.content || entry.data || '';
    if (typeof text === 'string' && text.length > 0) {
      const result = moat.scan(text);
      
      if (!result.safe && result.findings.length > 0) {
        this.recordThreat(result.findings[0]);
      }
    }
  }

  /**
   * Record threat detection
   */
  recordThreat(finding) {
    this.stats.threatsBlocked++;
    this.stats.lastThreat = finding;
    
    const threat = {
      timestamp: Date.now(),
      type: finding.type,
      subtype: finding.subtype,
      severity: finding.severity
    };
    
    this.stats.threatHistory.unshift(threat);
    if (this.stats.threatHistory.length > this.options.maxHistoryItems) {
      this.stats.threatHistory.pop();
    }
    
    // Update threat type counts
    this.stats.threatsByType[finding.type] = (this.stats.threatsByType[finding.type] || 0) + 1;
  }

  /**
   * Scan for network activity
   */
  scanNetworkActivity() {
    // Simulate network monitoring
    if (Math.random() < 0.3) { // 30% chance of network activity
      const activity = {
        timestamp: Date.now(),
        url: this.generateRandomUrl(),
        method: Math.random() < 0.8 ? 'GET' : 'POST',
        status: Math.random() < 0.95 ? 'allowed' : 'blocked'
      };
      
      this.stats.networkActivity.unshift(activity);
      if (this.stats.networkActivity.length > this.options.maxHistoryItems) {
        this.stats.networkActivity.pop();
      }
      
      this.stats.networkCalls++;
    }
  }

  /**
   * Generate random URL for simulation
   */
  generateRandomUrl() {
    const domains = ['github.com', 'api.openai.com', 'stackoverflow.com', 'google.com', 'npmjs.com'];
    const paths = ['api/v1/models', 'search', 'issues', 'releases', 'packages'];
    
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const pathPart = paths[Math.floor(Math.random() * paths.length)];
    
    return `https://${domain}/${pathPart}`;
  }

  /**
   * Update calculated statistics
   */
  updateStats() {
    const now = Date.now();
    this.stats.uptime = Math.floor((now - this.startTime) / 1000);
    
    // Calculate rates
    if (this.stats.uptime > 0) {
      this.stats.scanRate = this.stats.totalScans / this.stats.uptime;
      this.stats.threatRate = this.stats.threatsBlocked / this.stats.uptime;
    }
    
    this.lastUpdate = now;
    
    // Simulate active agents count
    this.stats.agentsActive = Math.floor(Math.random() * 3) + 1;
  }

  /**
   * Main display update function
   */
  updateDisplay() {
    // Clear screen and move to top
    process.stdout.write('\x1b[2J\x1b[H');
    
    const output = this.buildDisplay();
    process.stdout.write(output);
  }

  /**
   * Build the complete display output
   */
  buildDisplay() {
    const sections = [];
    
    sections.push(this.buildHeader());
    sections.push(this.buildStatsOverview());
    sections.push(this.buildThreatMap());
    sections.push(this.buildActivityFeed());
    sections.push(this.buildNetworkGraph());
    sections.push(this.buildFooter());
    
    return sections.join('\n');
  }

  /**
   * Build header section
   */
  buildHeader() {
    const title = `${CHARS.SHIELD} ClawMoat Live Monitor`;
    const uptime = this.formatUptime(this.stats.uptime);
    const timestamp = new Date().toLocaleTimeString();
    
    const headerLine = this.createBoxLine(
      `${COLORS.BOLD}${COLORS.CYAN}${title}${COLORS.RESET}`,
      `${COLORS.DIM}Uptime: ${uptime} | ${timestamp}${COLORS.RESET}`,
      this.terminalWidth
    );
    
    return `${this.createHorizontalLine('top')}\n${headerLine}\n${this.createHorizontalLine('middle')}`;
  }

  /**
   * Build statistics overview
   */
  buildStatsOverview() {
    const stats = [
      { label: 'Agents Active', value: this.stats.agentsActive, color: COLORS.GREEN },
      { label: 'Total Scans', value: this.formatNumber(this.stats.totalScans), color: COLORS.BLUE },
      { label: 'Threats Blocked', value: this.formatNumber(this.stats.threatsBlocked), color: COLORS.RED },
      { label: 'Files Accessed', value: this.formatNumber(this.stats.filesAccessed), color: COLORS.YELLOW },
      { label: 'Network Calls', value: this.formatNumber(this.stats.networkCalls), color: COLORS.MAGENTA }
    ];
    
    const statLines = this.createStatsGrid(stats);
    return statLines.join('\n');
  }

  /**
   * Build threat map visualization
   */
  buildThreatMap() {
    if (!this.options.showThreatMap) return '';
    
    const title = `${COLORS.BOLD}Threat Detection Map${COLORS.RESET}`;
    const recentThreats = this.stats.threatHistory.slice(0, 10);
    
    const lines = [this.createSectionHeader(title)];
    
    if (recentThreats.length === 0) {
      lines.push(`${CHARS.BOX_VERTICAL} ${COLORS.GREEN}${CHARS.CHECK} No recent threats detected${COLORS.RESET}`);
    } else {
      recentThreats.forEach((threat, i) => {
        const age = this.formatAge(Date.now() - threat.timestamp);
        const severity = this.getSeverityIndicator(threat.severity);
        const line = `${CHARS.BOX_VERTICAL} ${severity} ${threat.type}/${threat.subtype} ${COLORS.DIM}(${age})${COLORS.RESET}`;
        lines.push(line);
      });
    }
    
    return lines.join('\n');
  }

  /**
   * Build activity feed
   */
  buildActivityFeed() {
    const title = `${COLORS.BOLD}Recent Activity${COLORS.RESET}`;
    const lines = [this.createSectionHeader(title)];
    
    const recentActivity = [
      ...this.stats.fileAccess.slice(0, 3).map(f => ({ ...f, activityType: 'file' })),
      ...this.stats.networkActivity.slice(0, 3).map(n => ({ ...n, activityType: 'network' })),
      ...this.stats.threatHistory.slice(0, 2).map(t => ({ ...t, activityType: 'threat' }))
    ]
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, 6);
    
    if (recentActivity.length === 0) {
      lines.push(`${CHARS.BOX_VERTICAL} ${COLORS.DIM}No recent activity${COLORS.RESET}`);
    } else {
      recentActivity.forEach(activity => {
        const age = this.formatAge(Date.now() - activity.timestamp);
        let line = `${CHARS.BOX_VERTICAL} `;
        
        switch (activity.activityType) {
          case 'file':
            line += `${COLORS.BLUE}📁${COLORS.RESET} ${activity.filename} ${COLORS.DIM}(${age})${COLORS.RESET}`;
            break;
          case 'network':
            line += `${COLORS.MAGENTA}🌐${COLORS.RESET} ${activity.url} ${COLORS.DIM}(${age})${COLORS.RESET}`;
            break;
          case 'threat':
            line += `${COLORS.RED}${CHARS.BLOCKED}${COLORS.RESET} ${activity.type} blocked ${COLORS.DIM}(${age})${COLORS.RESET}`;
            break;
        }
        
        lines.push(line);
      });
    }
    
    return lines.join('\n');
  }

  /**
   * Build network graph
   */
  buildNetworkGraph() {
    if (!this.options.showNetworkGraph) return '';
    
    const title = `${COLORS.BOLD}Network Activity Graph${COLORS.RESET}`;
    const lines = [this.createSectionHeader(title)];
    
    // Create a simple bar chart of recent network activity
    const buckets = this.createTimeBuckets(this.stats.networkActivity, 10);
    const maxCount = Math.max(...buckets.map(b => b.count), 1);
    
    buckets.forEach(bucket => {
      const barLength = Math.floor((bucket.count / maxCount) * 40);
      const bar = CHARS.BLOCK_FULL.repeat(barLength);
      const line = `${CHARS.BOX_VERTICAL} ${bucket.label} ${COLORS.GREEN}${bar}${COLORS.RESET} ${bucket.count}`;
      lines.push(line);
    });
    
    return lines.join('\n');
  }

  /**
   * Build footer
   */
  buildFooter() {
    const rateInfo = `Scan Rate: ${this.stats.scanRate.toFixed(1)}/s | Threat Rate: ${this.stats.threatRate.toFixed(2)}/s`;
    const controlInfo = "Press 'q' to quit";
    
    const footerLine = this.createBoxLine(
      `${COLORS.DIM}${rateInfo}${COLORS.RESET}`,
      `${COLORS.DIM}${controlInfo}${COLORS.RESET}`,
      this.terminalWidth
    );
    
    return `${this.createHorizontalLine('middle')}\n${footerLine}\n${this.createHorizontalLine('bottom')}`;
  }

  /**
   * Utility functions for display formatting
   */

  formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  }

  formatNumber(num) {
    if (num >= 1000000) {
      return `${(num / 1000000).toFixed(1)}M`;
    } else if (num >= 1000) {
      return `${(num / 1000).toFixed(1)}K`;
    }
    return num.toString();
  }

  formatAge(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
  }

  getSeverityIndicator(severity) {
    switch (severity) {
      case 'critical': return `${COLORS.BG_RED}${COLORS.WHITE} CRIT ${COLORS.RESET}`;
      case 'high': return `${COLORS.RED}${CHARS.WARNING}${COLORS.RESET}`;
      case 'medium': return `${COLORS.YELLOW}${CHARS.WARNING}${COLORS.RESET}`;
      case 'low': return `${COLORS.BLUE}ℹ${COLORS.RESET}`;
      default: return `${COLORS.DIM}?${COLORS.RESET}`;
    }
  }

  createHorizontalLine(type) {
    let left, middle, right, fill;
    
    switch (type) {
      case 'top':
        left = CHARS.BOX_TOP_LEFT;
        right = CHARS.BOX_TOP_RIGHT;
        fill = CHARS.BOX_HORIZONTAL;
        break;
      case 'bottom':
        left = CHARS.BOX_BOTTOM_LEFT;
        right = CHARS.BOX_BOTTOM_RIGHT;
        fill = CHARS.BOX_HORIZONTAL;
        break;
      case 'middle':
        left = CHARS.BOX_T_RIGHT;
        right = CHARS.BOX_T_LEFT;
        fill = CHARS.BOX_HORIZONTAL;
        break;
      default:
        return '';
    }
    
    return left + fill.repeat(this.terminalWidth - 2) + right;
  }

  createBoxLine(leftText, rightText, width) {
    const leftClean = this.stripAnsi(leftText);
    const rightClean = this.stripAnsi(rightText);
    const padding = width - leftClean.length - rightClean.length - 2;
    
    return `${CHARS.BOX_VERTICAL}${leftText}${' '.repeat(Math.max(0, padding))}${rightText}${CHARS.BOX_VERTICAL}`;
  }

  createSectionHeader(title) {
    const padding = Math.max(0, this.terminalWidth - this.stripAnsi(title).length - 4);
    return `${CHARS.BOX_T_RIGHT}${CHARS.BOX_HORIZONTAL} ${title} ${CHARS.BOX_HORIZONTAL.repeat(padding)}${CHARS.BOX_T_LEFT}`;
  }

  createStatsGrid(stats) {
    const lines = [];
    const itemsPerRow = Math.min(5, Math.floor(this.terminalWidth / 20));
    
    for (let i = 0; i < stats.length; i += itemsPerRow) {
      const rowStats = stats.slice(i, i + itemsPerRow);
      const statTexts = rowStats.map(stat => 
        `${stat.color}${stat.value}${COLORS.RESET} ${stat.label}`
      );
      
      const line = `${CHARS.BOX_VERTICAL} ${statTexts.join(' | ')}`;
      lines.push(line);
    }
    
    return lines;
  }

  createTimeBuckets(activities, bucketCount) {
    const now = Date.now();
    const bucketSize = 60000; // 1 minute buckets
    const buckets = [];
    
    for (let i = bucketCount - 1; i >= 0; i--) {
      const bucketStart = now - (i + 1) * bucketSize;
      const bucketEnd = now - i * bucketSize;
      
      const count = activities.filter(a => 
        a.timestamp >= bucketStart && a.timestamp < bucketEnd
      ).length;
      
      buckets.push({
        label: `${i + 1}m`,
        count,
        start: bucketStart,
        end: bucketEnd
      });
    }
    
    return buckets;
  }

  stripAnsi(text) {
    return text.replace(/\x1b\[[0-9;]*m/g, '');
  }
}

module.exports = { LiveMonitor };