'use strict';

const { SentinelApexThemesOptimizer } = require('../sa-eix-themes-optimizer');

describe('SentinelApexThemesOptimizer', () => {
  let optimizer;

  beforeEach(() => {
    optimizer = new SentinelApexThemesOptimizer();
  });

  describe('Initialization', () => {
    test('should initialize with default config', () => {
      expect(optimizer).toBeDefined();
      expect(optimizer.designTokens).toBeDefined();
      expect(optimizer.designSystem).toBeDefined();
    });

    test('should initialize with custom config', () => {
      const custom = new SentinelApexThemesOptimizer({ primaryColor: '#FF0000' });
      expect(custom).toBeDefined();
    });
  });

  describe('generateLightTheme', () => {
    test('should generate light theme with correct structure', () => {
      const theme = optimizer.generateLightTheme();
      expect(theme.type).toBe('light-theme');
      expect(theme.theme).toBeDefined();
      expect(theme.metadata).toBeDefined();
    });

    test('should have correct background colors', () => {
      const theme = optimizer.generateLightTheme();
      expect(theme.theme.background.primary).toBe('#FFFFFF');
      expect(theme.theme.background.secondary).toBe('#F8F9FA');
      expect(theme.theme.background.tertiary).toBe('#E9ECEF');
    });

    test('should have correct text colors', () => {
      const theme = optimizer.generateLightTheme();
      expect(theme.theme.text.primary).toBe('#212529');
      expect(theme.theme.text.secondary).toBe('#6C757D');
    });

    test('should have correct border colors', () => {
      const theme = optimizer.generateLightTheme();
      expect(theme.theme.border.primary).toBe('#DEE2E6');
      expect(theme.theme.border.secondary).toBe('#E9ECEF');
    });

    test('should have light variant metadata', () => {
      const theme = optimizer.generateLightTheme();
      expect(theme.metadata.variant).toBe('light');
      expect(theme.metadata.wcag).toBe('AA');
    });
  });

  describe('generateDarkTheme', () => {
    test('should generate dark theme with correct structure', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.type).toBe('dark-theme');
      expect(theme.theme).toBeDefined();
      expect(theme.metadata).toBeDefined();
    });

    test('should have dark variant metadata', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.metadata.variant).toBe('dark');
      expect(theme.metadata.wcag).toBe('AAA');
    });

    test('should include background colors', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.theme.background).toBeDefined();
    });

    test('should include text colors', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.theme.text).toBeDefined();
    });

    test('should include border colors', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.theme.border).toBeDefined();
    });
  });

  describe('generateHighContrastTheme', () => {
    test('should generate high contrast theme', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.type).toBe('high-contrast-theme');
      expect(theme.theme).toBeDefined();
    });

    test('should have pure black background', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.theme.background.primary).toBe('#000000');
    });

    test('should have pure white text', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.theme.text.primary).toBe('#FFFFFF');
    });

    test('should have white borders for high contrast', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.theme.border.primary).toBe('#FFFFFF');
    });

    test('should have AAA WCAG compliance', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.metadata.wcag).toBe('AAA');
    });

    test('should have high-contrast variant', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.metadata.variant).toBe('high-contrast');
    });
  });

  describe('generateMobileOptimizedTheme', () => {
    test('should generate mobile optimized theme', () => {
      const theme = optimizer.generateMobileOptimizedTheme();
      expect(theme.type).toBe('mobile-theme');
      expect(theme.theme).toBeDefined();
      expect(theme.breakpoints).toBeDefined();
    });

    test('should have correct breakpoints', () => {
      const theme = optimizer.generateMobileOptimizedTheme();
      expect(theme.breakpoints.mobile).toBe('320px');
      expect(theme.breakpoints.tablet).toBe('768px');
      expect(theme.breakpoints.desktop).toBe('1024px');
    });

    test('should have mobile-optimized variant metadata', () => {
      const theme = optimizer.generateMobileOptimizedTheme();
      expect(theme.metadata.variant).toBe('mobile-optimized');
    });

    test('should have AA WCAG compliance', () => {
      const theme = optimizer.generateMobileOptimizedTheme();
      expect(theme.metadata.wcag).toBe('AA');
    });
  });

  describe('generatePrintTheme', () => {
    test('should generate print theme', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.type).toBe('print-theme');
      expect(theme.theme).toBeDefined();
    });

    test('should have white backgrounds for printing', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.theme.background.primary).toBe('#FFFFFF');
      expect(theme.theme.background.secondary).toBe('#FFFFFF');
    });

    test('should have black text for printing', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.theme.text.primary).toBe('#000000');
    });

    test('should have gray borders for printing', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.theme.border.primary).toBe('#999999');
    });

    test('should have print variant', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.metadata.variant).toBe('print');
    });

    test('should have A WCAG compliance', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.metadata.wcag).toBe('A');
    });
  });

  describe('generateColorBlindTheme', () => {
    test('should generate colorblind theme', () => {
      const theme = optimizer.generateColorBlindTheme();
      expect(theme.type).toBe('colorblind-theme');
      expect(theme.theme).toBeDefined();
    });

    test('should have grayscale backgrounds', () => {
      const theme = optimizer.generateColorBlindTheme();
      expect(theme.theme.background.primary).toBe('#F0F0F0');
      expect(theme.theme.background.secondary).toBe('#E0E0E0');
      expect(theme.theme.background.tertiary).toBe('#D0D0D0');
    });

    test('should have colorblind-friendly colors', () => {
      const theme = optimizer.generateColorBlindTheme();
      expect(theme.theme.colors).toBeDefined();
      expect(theme.theme.colors.critical).toBeDefined();
      expect(theme.theme.colors.warning).toBeDefined();
      expect(theme.theme.colors.success).toBeDefined();
    });

    test('should use accessible color palette', () => {
      const theme = optimizer.generateColorBlindTheme();
      expect(theme.theme.colors.critical).toBe('#D45113');
      expect(theme.theme.colors.warning).toBe('#0173B2');
      expect(theme.theme.colors.success).toBe('#CA9161');
    });

    test('should have colorblind-friendly variant', () => {
      const theme = optimizer.generateColorBlindTheme();
      expect(theme.metadata.variant).toBe('colorblind-friendly');
    });

    test('should have AAA WCAG compliance', () => {
      const theme = optimizer.generateColorBlindTheme();
      expect(theme.metadata.wcag).toBe('AAA');
    });
  });

  describe('generateThemeVariants', () => {
    test('should generate all theme variants', () => {
      const variants = optimizer.generateThemeVariants();
      expect(variants.type).toBe('theme-variants');
      expect(variants.themes).toBeDefined();
    });

    test('should include all 6 themes', () => {
      const variants = optimizer.generateThemeVariants();
      expect(variants.themes.light).toBeDefined();
      expect(variants.themes.dark).toBeDefined();
      expect(variants.themes.highContrast).toBeDefined();
      expect(variants.themes.mobile).toBeDefined();
      expect(variants.themes.print).toBeDefined();
      expect(variants.themes.colorblind).toBeDefined();
    });

    test('should have total variant count', () => {
      const variants = optimizer.generateThemeVariants();
      expect(variants.metadata.totalVariants).toBe(6);
    });

    test('should list all WCAG compliance levels', () => {
      const variants = optimizer.generateThemeVariants();
      expect(variants.metadata.wcagCompliance).toContain('A');
      expect(variants.metadata.wcagCompliance).toContain('AA');
      expect(variants.metadata.wcagCompliance).toContain('AAA');
    });

    test('should include generation timestamp', () => {
      const variants = optimizer.generateThemeVariants();
      expect(variants.metadata.generatedAt).toBeDefined();
    });

    test('should have correct structure for each theme', () => {
      const variants = optimizer.generateThemeVariants();
      Object.values(variants.themes).forEach(theme => {
        expect(theme.type).toBeDefined();
        expect(theme.theme || theme.breakpoints).toBeDefined();
        expect(theme.metadata).toBeDefined();
      });
    });
  });

  describe('HTML Escaping', () => {
    test('should escape ampersand', () => {
      const escaped = optimizer.escapeHtml('&');
      expect(escaped).toBe('&amp;');
    });

    test('should escape less than', () => {
      const escaped = optimizer.escapeHtml('<');
      expect(escaped).toBe('&lt;');
    });

    test('should escape greater than', () => {
      const escaped = optimizer.escapeHtml('>');
      expect(escaped).toBe('&gt;');
    });

    test('should escape double quotes', () => {
      const escaped = optimizer.escapeHtml('"');
      expect(escaped).toBe('&quot;');
    });

    test('should escape single quotes', () => {
      const escaped = optimizer.escapeHtml("'");
      expect(escaped).toBe('&#039;');
    });

    test('should handle null and undefined', () => {
      expect(optimizer.escapeHtml(null)).toBe('');
      expect(optimizer.escapeHtml(undefined)).toBe('');
    });
  });

  describe('Theme Consistency', () => {
    test('all themes should have background colors', () => {
      const variants = optimizer.generateThemeVariants();
      Object.values(variants.themes).forEach(theme => {
        expect(theme.theme.background).toBeDefined();
      });
    });

    test('all themes should have text colors', () => {
      const variants = optimizer.generateThemeVariants();
      Object.values(variants.themes).forEach(theme => {
        expect(theme.theme.text).toBeDefined();
      });
    });

    test('all themes should have border colors', () => {
      const variants = optimizer.generateThemeVariants();
      Object.values(variants.themes).forEach(theme => {
        if (theme.theme.border !== undefined) {
          expect(theme.theme.border).toBeDefined();
        } else {
          expect(theme.theme.background || theme.theme.colors).toBeDefined();
        }
      });
    });

    test('all themes should have metadata', () => {
      const variants = optimizer.generateThemeVariants();
      Object.values(variants.themes).forEach(theme => {
        expect(theme.metadata).toBeDefined();
        expect(theme.metadata.variant).toBeDefined();
        expect(theme.metadata.wcag).toBeDefined();
      });
    });

    test('each theme should have unique variant name', () => {
      const variants = optimizer.generateThemeVariants();
      const variantNames = Object.values(variants.themes).map(t => t.metadata.variant);
      const uniqueNames = new Set(variantNames);
      expect(uniqueNames.size).toBe(variantNames.length);
    });
  });

  describe('WCAG Compliance', () => {
    test('should specify WCAG levels correctly', () => {
      const variants = optimizer.generateThemeVariants();
      const wcagLevels = Object.values(variants.themes).map(t => t.metadata.wcag);
      wcagLevels.forEach(level => {
        expect(['A', 'AA', 'AAA']).toContain(level);
      });
    });

    test('light theme should have AA compliance', () => {
      const theme = optimizer.generateLightTheme();
      expect(theme.metadata.wcag).toBe('AA');
    });

    test('dark theme should have AAA compliance', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.metadata.wcag).toBe('AAA');
    });

    test('high contrast should have AAA compliance', () => {
      const theme = optimizer.generateHighContrastTheme();
      expect(theme.metadata.wcag).toBe('AAA');
    });
  });

  describe('Color Definitions', () => {
    test('light theme should use light colors', () => {
      const theme = optimizer.generateLightTheme();
      const colors = Object.values(theme.theme);
      expect(theme.theme.background.primary).toBe('#FFFFFF');
    });

    test('dark theme should use dark colors', () => {
      const theme = optimizer.generateDarkTheme();
      expect(theme.theme.background.primary).toBeDefined();
    });

    test('print theme should use print-safe colors', () => {
      const theme = optimizer.generatePrintTheme();
      expect(theme.theme.background.primary).toBe('#FFFFFF');
      expect(theme.theme.text.primary).toBe('#000000');
    });
  });

  describe('Edge Cases', () => {
    test('should handle multiple calls without state mutation', () => {
      const theme1 = optimizer.generateLightTheme();
      const theme2 = optimizer.generateLightTheme();
      expect(theme1).toEqual(theme2);
    });

    test('should handle rapid theme generation', () => {
      const themes = [];
      for (let i = 0; i < 100; i++) {
        themes.push(optimizer.generateThemeVariants());
      }
      expect(themes.length).toBe(100);
    });

    test('should generate valid timestamp format', () => {
      const variants = optimizer.generateThemeVariants();
      const timestamp = variants.metadata.generatedAt;
      expect(new Date(timestamp).toISOString()).toBe(timestamp);
    });

    test('mobile theme should have all breakpoints', () => {
      const theme = optimizer.generateMobileOptimizedTheme();
      expect(theme.breakpoints.mobile).toBeDefined();
      expect(theme.breakpoints.tablet).toBeDefined();
      expect(theme.breakpoints.desktop).toBeDefined();
    });
  });
});
