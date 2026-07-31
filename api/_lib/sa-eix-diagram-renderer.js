'use strict';

class SentinelApexEIXDiagramRenderer {
  constructor(brandingConfig = {}) {
    const defaults = this.getDefaultBranding();
    this.brandingConfig = {
      ...defaults,
      ...brandingConfig,
      colors: { ...defaults.colors, ...((brandingConfig && brandingConfig.colors) || {}) },
    };
  }

  getDefaultBranding() {
    return {
      colors: {
        primary: '#0A3A5C',
        secondary: '#1B5E8E',
        accent: '#FF6B35',
        critical: '#E74C3C',
        warning: '#F39C12',
        success: '#2ECC71',
        neutral: '#34495E',
        light: '#ECF0F1',
        dark: '#2C3E50',
      },
    };
  }

  renderAttackChain(diagram, options = {}) {
    const { width = 1200, height = 400, theme = 'dark' } = options;
    const stages = diagram.stages || [];

    if (!Array.isArray(stages) || stages.length === 0) {
      return this.renderPlaceholder('Attack Chain', 'No attack stages available', width, height, theme);
    }

    let svg = this.initSVG(width, height, theme);
    const stageWidth = width / (stages.length + 1);
    const centerY = height / 2;
    const circleRadius = 35;

    // Draw connecting lines
    for (let i = 0; i < stages.length - 1; i++) {
      const x1 = stageWidth * (i + 1) + circleRadius;
      const x2 = stageWidth * (i + 2) - circleRadius;
      svg += this.createLine(x1, centerY, x2, centerY, this.brandingConfig.colors.accent);
      svg += this.createArrow(x2, centerY);
    }

    // Draw stage circles
    for (let i = 0; i < stages.length; i++) {
      const x = stageWidth * (i + 1);
      const stage = stages[i];

      // Circle background
      svg += this.createCircle(x, centerY, circleRadius, this.brandingConfig.colors.primary);

      // Stage number/label
      const label = typeof stage === 'string' ? stage : (stage.name || `Stage ${i + 1}`);
      svg += this.createText(x, centerY, label, 12, '#FFF', 'bold');

      // Stage description (below)
      const description = typeof stage === 'object' ? stage.description : '';
      if (description) {
        svg += this.createText(x, centerY + 50, description, 11, this.getTextColor(theme), 'normal');
      }
    }

    svg += '</svg>';
    return svg;
  }

  renderKillChain(diagram, options = {}) {
    const { width = 1200, height = 450, theme = 'dark' } = options;
    const stages = diagram.stages || [];

    if (!Array.isArray(stages) || stages.length === 0) {
      return this.renderPlaceholder('Kill Chain', 'No kill chain stages available', width, height, theme);
    }

    let svg = this.initSVG(width, height, theme);
    const stageWidth = width / (stages.length + 1);
    const padding = 40;
    const boxWidth = stageWidth - 20;
    const boxHeight = height - (padding * 2);

    for (let i = 0; i < stages.length; i++) {
      const x = stageWidth * (i + 1) - boxWidth / 2;
      const y = padding;
      const stage = stages[i];

      // Box background
      const color = this.getStageColor(i, stages.length);
      svg += this.createRect(x, y, boxWidth, boxHeight, color, '#FFF');

      // Stage name
      const stageName = typeof stage === 'string' ? stage : (stage.name || `Stage ${i + 1}`);
      svg += this.createText(x + boxWidth / 2, y + 30, stageName, 13, this.getContrastColor(color), 'bold');

      // Stage details
      const details = typeof stage === 'object' ? stage.details : [];
      if (Array.isArray(details)) {
        let detailY = y + 65;
        for (const detail of details.slice(0, 3)) {
          svg += this.createText(x + 10, detailY, `• ${detail}`, 10, this.getContrastColor(color));
          detailY += 20;
        }
      }

      // Arrow to next stage
      if (i < stages.length - 1) {
        const arrowX = x + boxWidth + 5;
        svg += this.createArrow(arrowX, height / 2);
      }
    }

    svg += '</svg>';
    return svg;
  }

  renderMitreMatrix(diagram, options = {}) {
    const { width = 1400, height = 600, theme = 'dark' } = options;
    const tactics = diagram.tactics || {};

    const tacticsArray = Object.entries(tactics);
    if (tacticsArray.length === 0) {
      return this.renderPlaceholder('MITRE ATT&CK', 'No MITRE techniques available', width, height, theme);
    }

    let svg = this.initSVG(width, height, theme);
    const cellWidth = width / (tacticsArray.length + 1);
    const cellHeight = 80;
    const padding = 20;

    // Render tactics header
    for (let i = 0; i < tacticsArray.length; i++) {
      const [tactic] = tacticsArray[i];
      const x = (i + 1) * cellWidth + padding;
      const y = 20;

      svg += this.createRect(x, y, cellWidth - (padding * 2), cellHeight, this.brandingConfig.colors.primary, '#FFF');
      svg += this.createText(x + (cellWidth - padding * 2) / 2, y + 40, tactic, 12, '#FFF', 'bold');
    }

    // Render techniques
    for (let i = 0; i < tacticsArray.length; i++) {
      const [, techniques] = tacticsArray[i];
      const x = (i + 1) * cellWidth + padding;
      let y = cellHeight + 40;

      if (Array.isArray(techniques)) {
        for (const technique of techniques.slice(0, 5)) {
          const techName = typeof technique === 'string' ? technique : (technique.technique || '');
          svg += this.createRect(x, y, cellWidth - (padding * 2), 30, this.brandingConfig.colors.secondary, '#FFF');
          svg += this.createText(x + (cellWidth - padding * 2) / 2, y + 20, techName, 10, '#FFF');
          y += 35;
        }
      }
    }

    svg += '</svg>';
    return svg;
  }

  renderTimeline(diagram, options = {}) {
    const { width = 1200, height = 400, theme = 'dark' } = options;
    const events = diagram.events || [];

    if (!Array.isArray(events) || events.length === 0) {
      return this.renderPlaceholder('Timeline', 'No events available', width, height, theme);
    }

    let svg = this.initSVG(width, height, theme);
    const padding = 40;
    const timelineY = height / 2;
    const timelineStart = padding;
    const timelineEnd = width - padding;
    const timelineLength = timelineEnd - timelineStart;

    // Main timeline line
    svg += this.createLine(timelineStart, timelineY, timelineEnd, timelineY, this.brandingConfig.colors.primary);

    // Parse and sort events by date
    const sortedEvents = this.sortEventsByDate(events);

    for (let i = 0; i < sortedEvents.length; i++) {
      const event = sortedEvents[i];
      const position = i / Math.max(sortedEvents.length - 1, 1);
      const x = timelineStart + position * timelineLength;

      // Event marker circle
      svg += this.createCircle(x, timelineY, 8, this.brandingConfig.colors.accent);

      // Event date (alternating above/below timeline)
      const dateY = i % 2 === 0 ? timelineY - 40 : timelineY + 40;
      const date = event.date || '';
      svg += this.createText(x, dateY, date, 10, this.getTextColor(theme));

      // Event description
      const descY = i % 2 === 0 ? timelineY - 60 : timelineY + 60;
      const description = (event.event || '').substring(0, 30);
      if (description) {
        svg += this.createText(x, descY, description, 9, this.getTextColor(theme));
      }
    }

    svg += '</svg>';
    return svg;
  }

  renderInfrastructureGraph(diagram, options = {}) {
    const { width = 1200, height = 500, theme = 'dark' } = options;
    const nodes = diagram.nodes || [];

    if (!Array.isArray(nodes) || nodes.length === 0) {
      return this.renderPlaceholder('Infrastructure', 'No infrastructure nodes', width, height, theme);
    }

    let svg = this.initSVG(width, height, theme);
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 3;

    // Draw central hub
    svg += this.createCircle(centerX, centerY, 15, this.brandingConfig.colors.critical);
    svg += this.createText(centerX, centerY, 'C2', 9, '#FFF', 'bold');

    // Draw nodes in circle
    for (let i = 0; i < nodes.length; i++) {
      const angle = (i / nodes.length) * 2 * Math.PI;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);

      // Connection line to center
      svg += this.createLine(centerX, centerY, x, y, this.brandingConfig.colors.accent);

      // Node circle
      const nodeColor = this.brandingConfig.colors.warning;
      svg += this.createCircle(x, y, 12, nodeColor);

      // Node label
      const node = nodes[i];
      const label = typeof node === 'string' ? node.substring(0, 15) : (node.value || node.type || '');
      svg += this.createText(x, y + 25, label, 9, this.getTextColor(theme));
    }

    svg += '</svg>';
    return svg;
  }

  renderThreatActorNetwork(diagram, options = {}) {
    const { width = 1200, height = 500, theme = 'dark' } = options;
    const actors = diagram.actors || [];
    const campaigns = diagram.campaigns || [];

    if ((actors.length === 0 && campaigns.length === 0)) {
      return this.renderPlaceholder('Threat Actor Network', 'No threat actors or campaigns', width, height, theme);
    }

    let svg = this.initSVG(width, height, theme);
    const padding = 40;
    const contentWidth = width - (padding * 2);
    const contentHeight = height - (padding * 2);

    // Render threat actors (left side)
    const actorX = padding + contentWidth * 0.2;
    svg += this.createText(padding + 20, padding + 20, 'Threat Actors', 12, this.getTextColor(theme), 'bold');

    for (let i = 0; i < actors.length && i < 5; i++) {
      const y = padding + 50 + (i * 60);
      const actor = actors[i];
      const name = typeof actor === 'string' ? actor : (actor.name || '');

      svg += this.createRect(padding, y, contentWidth * 0.35, 40, this.brandingConfig.colors.secondary, '#FFF');
      svg += this.createText(actorX, y + 25, name, 11, '#FFF');
    }

    // Render campaigns (right side)
    const campaignX = padding + contentWidth * 0.65;
    svg += this.createText(padding + contentWidth * 0.5 + 20, padding + 20, 'Campaigns', 12, this.getTextColor(theme), 'bold');

    for (let i = 0; i < campaigns.length && i < 5; i++) {
      const y = padding + 50 + (i * 60);
      const campaign = campaigns[i];
      const name = typeof campaign === 'string' ? campaign : (campaign.name || '');

      svg += this.createRect(padding + contentWidth * 0.5, y, contentWidth * 0.35, 40, this.brandingConfig.colors.accent, '#000');
      svg += this.createText(campaignX, y + 25, name, 11, '#000');
    }

    svg += '</svg>';
    return svg;
  }

  renderBattlefieldVisualization(data, options = {}) {
    const { width = 1400, height = 600, theme = 'dark' } = options;

    let svg = this.initSVG(width, height, theme);
    const padding = 40;
    const cellSize = (width - (padding * 2)) / 10;
    const cellHeight = (height - (padding * 2)) / 6;

    // Title
    svg += this.createText(width / 2, padding + 20, 'Threat Intelligence Battlefield', 14, this.getTextColor(theme), 'bold');

    // Render threat heatmap grid
    for (let row = 0; row < 6; row++) {
      for (let col = 0; col < 10; col++) {
        const x = padding + col * cellSize;
        const y = padding + 40 + row * cellHeight;

        // Random intensity for visualization
        const intensity = Math.floor(Math.random() * 5);
        const colors = [
          this.brandingConfig.colors.success,
          '#FFD700',
          '#FF8C00',
          '#FF4500',
          this.brandingConfig.colors.critical,
        ];
        const color = colors[intensity];

        svg += this.createRect(x, y, cellSize - 2, cellHeight - 2, color, 'none', 0.7);
      }
    }

    svg += '</svg>';
    return svg;
  }

  renderPlaceholder(title, message, width, height, theme) {
    let svg = this.initSVG(width, height, theme);
    svg += this.createText(width / 2, height / 2 - 20, title, 16, this.getTextColor(theme), 'bold');
    svg += this.createText(width / 2, height / 2 + 20, message, 12, this.getTextColor(theme));
    svg += '</svg>';
    return svg;
  }

  // SVG Primitive Methods

  initSVG(width, height, theme) {
    const bgColor = theme === 'dark' ? '#161B22' : '#FFFFFF';
    return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
      <rect width="${width}" height="${height}" fill="${bgColor}"/>`;
  }

  createLine(x1, y1, x2, y2, color = '#333', strokeWidth = 2) {
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${strokeWidth}"/>`;
  }

  createCircle(cx, cy, r, fill = '#333', stroke = 'none', strokeWidth = 1) {
    return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="${strokeWidth}"/>`;
  }

  createRect(x, y, width, height, fill = '#333', stroke = 'none', opacity = 1) {
    const opacityAttr = opacity < 1 ? ` opacity="${opacity}"` : '';
    return `<rect x="${x}" y="${y}" width="${width}" height="${height}" fill="${fill}" stroke="${stroke}" rx="4"${opacityAttr}/>`;
  }

  createText(x, y, text, fontSize = 12, fill = '#000', fontWeight = 'normal') {
    const sanitized = this.escapeXml(text);
    return `<text x="${x}" y="${y}" font-size="${fontSize}" fill="${fill}" text-anchor="middle" font-weight="${fontWeight}">${sanitized}</text>`;
  }

  createArrow(x, y, size = 10) {
    const points = `${x},${y} ${x - size},${y - size/2} ${x - size},${y + size/2}`;
    return `<polygon points="${points}" fill="${this.brandingConfig.colors.accent}"/>`;
  }

  // Utility Methods

  escapeXml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  getTextColor(theme) {
    return theme === 'dark' ? '#C9D1D9' : '#2C3E50';
  }

  getContrastColor(backgroundColor) {
    const rgb = this.hexToRgb(backgroundColor);
    if (!rgb) return '#000';
    const brightness = (rgb.r * 299 + rgb.g * 587 + rgb.b * 114) / 1000;
    return brightness > 155 ? '#000' : '#FFF';
  }

  hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16),
    } : null;
  }

  getStageColor(index, total) {
    const colors = [
      this.brandingConfig.colors.primary,
      this.brandingConfig.colors.secondary,
      this.brandingConfig.colors.accent,
      this.brandingConfig.colors.warning,
      this.brandingConfig.colors.critical,
    ];
    return colors[index % colors.length];
  }

  sortEventsByDate(events) {
    if (!Array.isArray(events)) return [];
    return events.slice().sort((a, b) => {
      const dateA = new Date(a.date || 0);
      const dateB = new Date(b.date || 0);
      return dateA - dateB;
    });
  }
}

module.exports = { SentinelApexEIXDiagramRenderer };
