module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/lib'],
  testMatch: ['**/__tests__/**/*.ts', '**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  collectCoverageFrom: [
    'lib/**/*.ts',
    '!lib/**/*.d.ts',
    '!lib/**/index.ts',
    '!**/node_modules/**',
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  testTimeout: 30000,
  maxWorkers: '50%',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: false,
      isolatedModules: true,
      tsconfig: {
        target: 'ES2020',
        module: 'commonjs',
        lib: ['ES2020'],
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true,
        types: ['jest', 'node'],
      },
    }],
  },
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/lib/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
};
