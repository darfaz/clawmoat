/**
 * ClawMoat Security Score Badge Generator
 * 
 * Generates shields.io-style SVG badges based on audit/scan results.
 */

const GRADES = {
  'A+': { color: '#10B981', label: 'excellent' },
  'A':  { color: '#10B981', label: 'great' },
  'B':  { color: '#84CC16', label: 'good' },
  'C':  { color: '#F59E0B', label: 'fair' },
  'D':  { color: '#EF4444', label: 'poor' },
  'F':  { color: '#DC2626', label: 'failing' },
};

/**
 * Calculate security grade from scan/audit findings.
 * @param {object} opts
 * @param {number} opts.totalFindings - Total number of findings
 * @param {number} opts.criticalFindings - Number of critical/high findings
 * @param {number} opts.filesScanned - Number of files scanned
 * @returns {string} Grade (A+ through F)
 */
function calculateGrade({ totalFindings = 0, criticalFindings = 0, filesScanned = 1 }) {
  if (totalFindings === 0) return 'A+';
  const ratio = totalFindings / Math.max(filesScanned, 1);
  if (criticalFindings > 0) {
    return criticalFindings >= 3 ? 'F' : 'D';
  }
  if (ratio <= 0.05) return 'A';
  if (ratio <= 0.15) return 'B';
  if (ratio <= 0.3) return 'C';
  if (ratio <= 0.5) return 'D';
  return 'F';
}

/**
 * Generate an SVG badge string.
 * @param {string} grade - The security grade (A+, A, B, C, D, F)
 * @returns {string} SVG markup
 */
function generateBadgeSVG(grade) {
  const g = GRADES[grade] || GRADES['F'];
  const gradeText = grade.replace('+', '&#43;');
  const labelWidth = 138;
  const gradeWidth = 40;
  const totalWidth = labelWidth + gradeWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="ClawMoat Security Score: ${grade}">
  <title>ClawMoat Security Score: ${grade}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#0F172A"/>
    <rect x="${labelWidth}" width="${gradeWidth}" height="20" fill="${g.color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">🏰 ClawMoat Score</text>
    <text x="${labelWidth / 2}" y="14">🏰 ClawMoat Score</text>
    <text aria-hidden="true" x="${labelWidth + gradeWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${gradeText}</text>
    <text x="${labelWidth + gradeWidth / 2}" y="14" font-weight="bold">${gradeText}</text>
  </g>
</svg>`;
}

/**
 * Get a shields.io URL for the given grade.
 * @param {string} grade
 * @returns {string} shields.io badge URL
 */
function getShieldsURL(grade) {
  const colorMap = {
    'A+': 'brightgreen', 'A': 'green', 'B': 'yellowgreen',
    'C': 'yellow', 'D': 'orange', 'F': 'red',
  };
  const encoded = encodeURIComponent(grade);
  const color = colorMap[grade] || 'red';
  return `https://img.shields.io/badge/ClawMoat-${encoded}-${color}`;
}

module.exports = { calculateGrade, generateBadgeSVG, getShieldsURL, GRADES };
