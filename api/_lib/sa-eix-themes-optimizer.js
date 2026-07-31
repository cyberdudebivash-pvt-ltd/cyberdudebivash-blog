'use strict';

const { SentinelApexEIXDesignSystem } = require('./sa-eix-design-system');

class SentinelApexThemesOptimizer {
  constructor(brandingConfig = {}) {
    this.brandingConfig = { ...brandingConfig };
    this.designSystem = new SentinelApexEIXDesignSystem(brandingConfig);
    this.designTokens = this.designSystem.tokens;
  }

  generateLightTheme() {
    return {
      type: 'light-theme',
      theme: {
        background: {
          primary: '#FFFFFF',
          secondary: '#F8F9FA',
          tertiary: '#E9ECEF',
        },
        text: {
          primary: '#212529',
          secondary: '#6C757D',
        },
        border: {
          primary: '#DEE2E6',
          secondary: '#E9ECEF',
        },
      },
      metadata: { variant: 'light', wcag: 'AA' },
    };
  }

  generateDarkTheme() {
    return {
      type: 'dark-theme',
      theme: this.designSystem.themes.dark,
      metadata: { variant: 'dark', wcag: 'AAA' },
    };
  }

  generateHighContrastTheme() {
    return {
      type: 'high-contrast-theme',
      theme: {
        background: {
          primary: '#000000',
          secondary: '#1a1a1a',
          tertiary: '#333333',
        },
        text: {
          primary: '#FFFFFF',
          secondary: '#CCCCCC',
        },
        border: {
          primary: '#FFFFFF',
          secondary: '#CCCCCC',
        },
      },
      metadata: { variant: 'high-contrast', wcag: 'AAA' },
    };
  }

  generateMobileOptimizedTheme() {
    return {
      type: 'mobile-theme',
      theme: this.designSystem.themes.dark,
      breakpoints: {
        mobile: '320px',
        tablet: '768px',
        desktop: '1024px',
      },
      metadata: { variant: 'mobile-optimized', wcag: 'AA' },
    };
  }

  generatePrintTheme() {
    return {
      type: 'print-theme',
      theme: {
        background: {
          primary: '#FFFFFF',
          secondary: '#FFFFFF',
          tertiary: '#F0F0F0',
        },
        text: {
          primary: '#000000',
          secondary: '#333333',
        },
        border: {
          primary: '#999999',
          secondary: '#CCCCCC',
        },
      },
      metadata: { variant: 'print', wcag: 'A' },
    };
  }

  generateColorBlindTheme() {
    return {
      type: 'colorblind-theme',
      theme: {
        background: {
          primary: '#F0F0F0',
          secondary: '#E0E0E0',
          tertiary: '#D0D0D0',
        },
        text: {
          primary: '#000000',
          secondary: '#333333',
        },
        colors: {
          critical: '#D45113',
          warning: '#0173B2',
          success: '#CA9161',
          accent: ['#999999'],
        },
      },
      metadata: { variant: 'colorblind-friendly', wcag: 'AAA' },
    };
  }

  generateThemeVariants() {
    return {
      type: 'theme-variants',
      themes: {
        light: this.generateLightTheme(),
        dark: this.generateDarkTheme(),
        highContrast: this.generateHighContrastTheme(),
        mobile: this.generateMobileOptimizedTheme(),
        print: this.generatePrintTheme(),
        colorblind: this.generateColorBlindTheme(),
      },
      metadata: {
        totalVariants: 6,
        wcagCompliance: ['A', 'AA', 'AAA'],
        generatedAt: new Date().toISOString(),
      },
    };
  }

  escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

module.exports = { SentinelApexThemesOptimizer };
